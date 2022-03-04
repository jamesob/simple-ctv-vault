#!/usr/bin/env python3
import struct
import json
import hashlib
from pprint import pformat
import typing as t
from dataclasses import dataclass
from pathlib import Path

from bitcoin import base58, SelectParams, wallet
from bitcoin.core import (
    CTransaction,
    CMutableTransaction,
    CMutableTxIn,
    CTxIn,
    CTxOut,
    CScript,
    COutPoint,
    CTxWitness,
    CTxInWitness,
    CScriptWitness,
    COIN,
    lx,
)
from bitcoin.rpc import RawProxy, JSONRPCError
from bitcoin.core import script
from bitcoin.core.script import (
    OP_0,
    OP_DROP,
    OP_CHECKSIG,
    OP_NOP4,
    OP_IF,
    OP_CHECKSEQUENCEVERIFY,
    OP_ELSE,
    OP_ENDIF,
    OP_FALSE,
    OP_TRUE,
    SignatureHash,
    SIGHASH_ALL,
    SIGVERSION_WITNESS_V0,
)
from bitcoin.core.serialize import Hash160
from bitcoin.core.key import CPubKey
from bitcoin.wallet import (
    CBech32BitcoinAddress,
    CKey,
    P2WPKHBitcoinAddress,
    CBitcoinSecret,
)
from bitcoin.bech32 import CBech32Data
from buidl.hd import HDPrivateKey, PrivateKey
from buidl.ecc import S256Point


OP_CHECKTEMPLATEVERIFY = OP_NOP4
Sats = int
SatsPerByte = int


# Mutable globals
fee_wallet = None
balance_wallet = None
cold_wallet = None
hot_wallet = None
rpc: RawProxy = None


@dataclass(frozen=True)
class Coin:
    outpoint: COutPoint
    amount: Sats
    scriptPubKey: bytes
    height: int


@dataclass
class Wallet:
    privkey: PrivateKey
    coins: t.List[Coin]
    network: str

    @classmethod
    def generate(cls, seed: bytes, network: str = "regtest") -> "Wallet":
        return cls(
            HDPrivateKey.from_seed(seed, network=network).get_private_key(1),
            [],
            network,
        )

    def fund(self, rpc: RawProxy) -> Coin:
        fund_addr = self.privkey.point.p2wpkh_address(network=self.network)
        rpc.generatetoaddress(110, fund_addr)

        scan = scan_utxos(rpc, fund_addr)
        assert scan["success"]

        for utxo in scan["unspents"]:
            self.coins.append(
                Coin(
                    COutPoint(txid_to_bytes(utxo["txid"]), utxo["vout"]),
                    int(utxo["amount"] * COIN),
                    bytes.fromhex(utxo["scriptPubKey"]),
                    utxo["height"],
                )
            )

        # Earliest coins first.
        self.coins.sort(key=lambda i: i.height)
        return self.coins.pop(0)


def txid_to_bytes(txid: str) -> bytes:
    """Convert the txids output by Bitcoin Core (little endian) to bytes."""
    return bytes.fromhex(txid)[::-1]


def configure_for_regtest():
    global fee_wallet
    global balance_wallet
    global cold_wallet
    global hot_wallet
    global rpc
    SelectParams("regtest")

    rpc = RawProxy()
    fee_wallet = Wallet.generate(b"fee")
    balance_wallet = Wallet.generate(b"balance")
    cold_wallet = Wallet.generate(b"cold")
    hot_wallet = Wallet.generate(b"hot")

    balance_wallet.fund(rpc)
    return rpc


def scan_utxos(rpc, addr):
    return rpc.scantxoutset("start", [f"addr({addr})"])


# For use with template transactions.
BLANK_INPUT = CMutableTxIn
Txid = str
RawTxStr = str


@dataclass
class VaultPlan:
    """
          output you're spending from              amount0
                     |
             to_vault_tx output                    amount1
                (<H> OP_CTV)
                     |
                 unvault_tx                        amount2
        (OP_CSV hot_pk | (<H(to_cold_tx)> OP_CTV)
              /               \
        to_hot_tx           to_cold_tx
                        (cold_pk OP_CHECKSIG)      amount3

    """

    # SEC-encoded public keys associated with various identities in the vault scheme.
    hot_pubkey: S256Point
    cold_pubkey: S256Point
    fees_pubkey: S256Point

    # The amount being committed to the vault.
    amount_in: Sats

    # How many blocks to delay the vault -> hot PK path.
    block_delay: int

    # What percentage of the amount are we taking in fees at each step of the vault?
    # Note this isn't how you'd actually do it (would want to specify feerate),
    # but is a simplification for this demo.
    # fee_perc: float = 0.01

    def amount_at_step(self, step=0) -> Sats:
        """
        Compute the amount at each step of the vault, per
        "amount[n]" in the diagram above.
        """
        sats_per_step = 10000
        return self.amount_in - (sats_per_step * step)

    def to_vault_tx(
        self,
        spend_from_addr: bytes,
        p2wpkh_outpoint: COutPoint,
        spend_from_key: PrivateKey,
    ) -> CTransaction:
        """
        Spend from a P2WPKH output into a new vault.
        """
        tx = CMutableTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(p2wpkh_outpoint, nSequence=0)]  # signal for RBF
        tx.vout = [CTxOut(self.amount_at_step(1), self.to_vault_script)]

        # Standard p2wpkh redeemScript
        redeem_script = CScript(
            [
                script.OP_DUP,
                script.OP_HASH160,
                spend_from_addr,
                script.OP_EQUALVERIFY,
                script.OP_CHECKSIG,
            ]
        )

        sighash = SignatureHash(
            redeem_script,
            tx,
            0,  # input index
            SIGHASH_ALL,
            amount=self.amount_in,
            sigversion=SIGVERSION_WITNESS_V0,
        )

        sig = spend_from_key.sign(int.from_bytes(sighash, "big")).der() + bytes(
            [SIGHASH_ALL]
        )
        wit = [CTxInWitness(CScriptWitness([sig, spend_from_key.point.sec()]))]
        tx.wit = CTxWitness(wit)
        return CTransaction.from_tx(tx)

    @property
    def to_vault_script(self) -> CScript:
        return CScript([self.unvault_ctv_hash, OP_CHECKTEMPLATEVERIFY])

    @property
    def unvault_ctv_hash(self) -> bytes:
        """Return the CTV hash for the unvaulting transaction."""
        return get_standard_template_hash(self.unvault_tx_template, 0)

    @property
    def unvault_tx_template(self) -> CMutableTransaction:
        """
        Return the transaction that initiates the unvaulting process.

        Once this transaction is broadcast, we can either spend to the hot wallet
        with a delay or immediately sweep funds to the cold wallet.

        Note that the particular `vin` value still needs to be filled in, though
        it doesn't matter for the purposes of computing the CTV hash.
        """
        # Used to compute CTV hashes, but not used in any final transactions.
        tx = CMutableTransaction()
        tx.nVersion = 2
        # We can leave this as a dummy input, since the coin we're spending here is
        # encumbered solely by CTV, e.g.
        #
        #   `<H> OP_CTV`
        #
        # and so doesn't require any kind of scriptSig. Subsequently, it won't affect the
        # hash of this transaction.
        tx.vin = [BLANK_INPUT()]
        tx.vout = [
            CTxOut(
                self.amount_at_step(2),
                # Standard P2WSH output:
                CScript([OP_0, sha256(self.unvault_redeemScript)]),
            )
        ]
        return tx

    @property
    def unvault_redeemScript(self) -> CScript:
        return CScript(
            [
                # fmt: off
                OP_IF,
                    self.block_delay, OP_CHECKSEQUENCEVERIFY, OP_DROP,
                    self.hot_pubkey.sec(), OP_CHECKSIG,
                OP_ELSE,
                    self.to_cold_ctv_hash, OP_CHECKTEMPLATEVERIFY,
                OP_ENDIF,
                # fmt: on
            ]
        )

    def unvault_tx(self, vault_outpoint: COutPoint) -> CTransaction:
        tx = self.unvault_tx_template
        tx.vin = [CTxIn(vault_outpoint)]
        return CTransaction.from_tx(tx)

    @property
    def to_cold_tx_template(self) -> CMutableTransaction:
        """Return the transaction that sweeps vault funds to the cold destination."""
        # scriptSig consists of a single push-0 to control the if-block above.
        return txn_p2wpkh(
            [CTxIn()],  # blank scriptSig when spending P2WSH
            self.amount_at_step(3),
            pay_to_h160=self.cold_pubkey.hash160(),
            fee_mgmt_pay_to_h160=self.fees_pubkey.hash160(),
        )

    @property
    def to_cold_ctv_hash(self) -> bytes:
        return get_standard_template_hash(self.to_cold_tx_template, 0)

    def to_cold_tx(self, unvault_outpoint: COutPoint) -> CTransaction:
        tx = self.to_cold_tx_template
        tx.vin = [CTxIn(unvault_outpoint)]

        # Use the amount from the last step for the sighash.
        witness = CScriptWitness([b'', self.unvault_redeemScript])
        tx.wit = CTxWitness([CTxInWitness(witness)])

        return CTransaction.from_tx(tx)

    @property
    def to_hot_tx_template(self) -> CMutableTransaction:
        return txn_p2wpkh(
            [BLANK_INPUT()],
            self.amount_at_step(3),
            pay_to_h160=self.hot_pubkey.hash160(),
            fee_mgmt_pay_to_h160=self.fees_pubkey.hash160(),
        )

    def to_hot_tx(self, unvault_outpoint: COutPoint, hot_priv: PrivateKey) -> CTransaction:
        tx = self.to_hot_tx_template
        tx.vin = [CTxIn(unvault_outpoint, nSequence=self.block_delay)]

        sighash = SignatureHash(
            self.unvault_redeemScript,
            tx,
            0,
            SIGHASH_ALL,
            amount=self.amount_at_step(2),  # the prior step amount
            sigversion=SIGVERSION_WITNESS_V0,
        )
        sig = hot_priv.sign(int.from_bytes(sighash, 'big')).der() + bytes([SIGHASH_ALL])
        witness = CScriptWitness([sig, b'\x01', self.unvault_redeemScript])
        tx.wit = CTxWitness([CTxInWitness(witness)])

        return CTransaction.from_tx(tx)


@dataclass
class VaultExecutor:
    plan: VaultPlan
    rpc: RawProxy

    vault_txid: t.Optional[str] = None
    unvault_txid: t.Optional[str] = None

    def send_to_vault(self, coin: Coin, spend_key: PrivateKey) -> RawTxStr:
        spend_addr = CBech32BitcoinAddress.from_scriptPubKey(CScript(coin.scriptPubKey))
        print(f"\n# Sending to vault\n")

        print(f"Spending coin ({spend_addr})\n  {coin}\ninto vault")
        tx = self.plan.to_vault_tx(spend_addr, coin.outpoint, spend_key)
        print(f"Transaction:\n{pformat(tx)}\n")
        hx = tx.serialize().hex()
        print(f"Raw hex: {hx}")

        txid = rpc.sendrawtransaction(hx)
        self.vault_txid = txid

        print("Coins are vaulted!")
        print(f"Txid accepted: {self.vault_txid}")
        print(f"Scan for the vault scriptpubkey: {tx.vout[0].scriptPubKey.hex()}")
        print(
            f"Scan for the unvault scriptpubkey: {self.plan.unvault_tx_template.vout[0].scriptPubKey.hex()}"
        )
        return txid

    def start_unvault(self):
        assert self.vault_txid
        print(f"\n# Starting unvault\n")

        tx = self.plan.unvault_tx(COutPoint(txid_to_bytes(self.vault_txid), 0))
        hx = tx.serialize().hex()
        print(f"\nTransaction:\n{tx}")
        print(f"\nRaw hex:\n{hx}")

        txid = rpc.sendrawtransaction(hx)
        self.unvault_txid = txid
        return txid

    def sweep_to_cold(self):
        assert self.unvault_txid
        cold_addr = self.plan.cold_pubkey.p2wpkh_address('regtest')  # TODO network
        print(f"\n# Sweep to cold ({cold_addr})\n")

        tx = self.plan.to_cold_tx(COutPoint(txid_to_bytes(self.unvault_txid), 0))
        hx = tx.serialize().hex()
        print(f"\nTransaction:\n{tx}")
        print(f"\nRaw hex:\n{hx}")

        return

    def sweep_to_hot(self, hot_privkey):
        assert self.unvault_txid
        hot_addr = self.plan.hot_pubkey.p2wpkh_address('regtest')  # TODO network
        print(f"\n\n# Sweep to hot ({hot_addr})")

        tx = self.plan.to_hot_tx(
            COutPoint(txid_to_bytes(self.unvault_txid), 0), hot_privkey)
        hx = tx.serialize().hex()
        print(f"\nTransaction:\n{tx}")
        print(f"\nRaw hex:\n{hx}")

        return

def txn_p2wpkh(
    vin: t.List[CTxIn], nValue: int, pay_to_h160: bytes, fee_mgmt_pay_to_h160: bytes
) -> CMutableTransaction:
    pay_to_script = CScript([OP_0, pay_to_h160])
    assert pay_to_script.is_witness_v0_keyhash()

    pay_to_fee_script = CScript([OP_0, fee_mgmt_pay_to_h160])
    assert pay_to_fee_script.is_witness_v0_keyhash()

    tx = CMutableTransaction()
    tx.nVersion = 2
    tx.vin = vin
    tx.vout = [
        CTxOut(nValue, pay_to_script),
        # Anchor output for CPFP-based fee bumps
        # CTxOut(0, pay_to_fee_script),
    ]
    return tx


def sha256(s) -> bytes:
    return hashlib.sha256(s).digest()


def ser_compact_size(l) -> bytes:
    r = b""
    if l < 253:
        r = struct.pack("B", l)
    elif l < 0x10000:
        r = struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        r = struct.pack("<BI", 254, l)
    else:
        r = struct.pack("<BQ", 255, l)
    return r


def ser_string(s) -> bytes:
    return ser_compact_size(len(s)) + s


def get_standard_template_hash(tx: CTransaction, nIn: int) -> bytes:
    r = b""
    r += struct.pack("<i", tx.nVersion)
    r += struct.pack("<I", tx.nLockTime)
    if any(inp.scriptSig for inp in tx.vin):
        r += sha256(b"".join(ser_string(inp.scriptSig) for inp in tx.vin))
    r += struct.pack("<I", len(tx.vin))
    r += sha256(b"".join(struct.pack("<I", inp.nSequence) for inp in tx.vin))
    r += struct.pack("<I", len(tx.vout))
    r += sha256(b"".join(out.serialize() for out in tx.vout))
    r += struct.pack("<I", nIn)
    return sha256(r)


def main():
    rpc = configure_for_regtest()
    coin = balance_wallet.fund(rpc)
    plan = VaultPlan(
        hot_wallet.privkey.point,
        cold_wallet.privkey.point,
        fee_wallet.privkey.point,
        coin.amount,
        block_delay=10,
    )
    exec = VaultExecutor(plan, rpc)
    exec.send_to_vault(coin, balance_wallet.privkey)
    exec.start_unvault()
    exec.sweep_to_cold()
    exec.sweep_to_hot(hot_wallet.privkey)


def basic_spend(addr: str, privkey: bytes, txid: str, input_amount_sats: int):
    key = CBitcoinSecret(privkey)
    MIN_RELAY_FEE = 110
    amt = input_amount_sats - MIN_RELAY_FEE
    out_scriptpubkey = CScript([OP_0, Hash160(key.pub)])
    assert out_scriptpubkey.is_witness_v0_keyhash()

    gen_addr = P2WPKHBitcoinAddress.from_scriptPubKey(out_scriptpubkey)
    assert addr == str(gen_addr)

    tx = CMutableTransaction()
    tx.nVersion = 2
    tx.vin = [CTxIn(COutPoint(lx(txid), 0))]
    tx.vout = [CTxOut(amt, out_scriptpubkey)]

    redeem_script = gen_addr.to_redeemScript()
    sighash = SignatureHash(
        redeem_script,
        tx,
        0,
        SIGHASH_ALL,
        amount=input_amount_sats,
        sigversion=SIGVERSION_WITNESS_V0,
    )

    sig = key.sign(sighash) + bytes([SIGHASH_ALL])
    wit = [CTxInWitness(CScriptWitness([sig, key.pub]))]
    tx.wit = CTxWitness(wit)

    print(f"sending {amt} -> {str(gen_addr)}")
    print(tx.serialize().hex())


def _pytest_ctv_hash():
    data = json.loads(Path("ctvhash-test-vectors.json").read_bytes())[1:-1]
    tests = 0

    for case in data:
        tx = CTransaction.deserialize(bytearray.fromhex(case["hex_tx"]))

        for idx, res in zip(case["spend_index"], case["result"]):
            assert get_standard_template_hash(tx, idx).hex() == res
            tests += 1

    print(tests)
    assert tests > 0


if __name__ == "__main__":
    main()
