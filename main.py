#!/usr/bin/env python3
import struct
import hashlib
import sys
import typing as t
from dataclasses import dataclass

from bitcoin import SelectParams
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
)
from bitcoin.core import script
from bitcoin.wallet import CBech32BitcoinAddress
from buidl.hd import HDPrivateKey, PrivateKey
from buidl.ecc import S256Point, G
from rpc import BitcoinRPC
from clii import App


cli = App()

OP_CHECKTEMPLATEVERIFY = script.OP_NOP4
Sats = int
SatsPerByte = int


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

    def fund(self, rpc: BitcoinRPC) -> Coin:
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
        self.coins = [
            c for c in sorted(self.coins, key=lambda i: i.height) if c.amount > COIN
        ]
        try:
            return self.coins.pop(0)
        except IndexError:
            raise RuntimeError(
                "Your regtest is out of subsidy - "
                "please wipe the datadir and restart."
            )


# For use with template transactions.
BLANK_INPUT = CMutableTxIn
Txid = str
RawTxStr = str


@dataclass
class VaultPlan:
    """
    Tempalte and generate transactions for a one-hop vault structure based on
    OP_CHECKTEMPLATEVERIFY.


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
    fees_per_step: Sats = 10000

    def amount_at_step(self, step=0) -> Sats:
        """
        Compute the amount at each step of the vault, per
        "amount[n]" in the diagram above.
        """
        # In reality, you'd compute feerate per step and use that. (TODO)
        amt = self.amount_in - (self.fees_per_step * step)
        assert amt > 0
        return amt

    def to_vault_tx(
        self,
        spend_from_addr: bytes,
        p2wpkh_outpoint: COutPoint,
        spend_from_key: PrivateKey,
    ) -> CTransaction:
        """
        Spend from a P2WPKH output into a new vault.

        The output is a bare OP_CTV script, which consumes less chain space
        than a P2(W)SH.
        """
        tx = CMutableTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(p2wpkh_outpoint, nSequence=0)]  # signal for RBF
        tx.vout = [
            CTxOut(
                self.amount_at_step(1),
                CScript([self.unvault_ctv_hash, OP_CHECKTEMPLATEVERIFY]),
            )
        ]

        # Standard p2wpkh redeemScript
        redeem_script = CScript(
            [
                script.OP_DUP, script.OP_HASH160, spend_from_addr,
                script.OP_EQUALVERIFY, script.OP_CHECKSIG,
            ]
        )

        sighash = script.SignatureHash(
            redeem_script,
            tx,
            0,  # input index
            script.SIGHASH_ALL,
            amount=self.amount_in,
            sigversion=script.SIGVERSION_WITNESS_V0,
        )

        sig = spend_from_key.sign(int.from_bytes(sighash, "big")).der() + bytes(
            [script.SIGHASH_ALL]
        )
        wit = [CTxInWitness(CScriptWitness([sig, spend_from_key.point.sec()]))]
        tx.wit = CTxWitness(wit)
        return CTransaction.from_tx(tx)

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
                CScript([script.OP_0, sha256(self.unvault_redeemScript)]),
            )
        ]
        return tx

    @property
    def unvault_redeemScript(self) -> CScript:
        return CScript(
            [
                # fmt: off
                script.OP_IF,
                    self.block_delay, script.OP_CHECKSEQUENCEVERIFY, script.OP_DROP,
                    self.hot_pubkey.sec(), script.OP_CHECKSIG,
                script.OP_ELSE,
                    self.to_cold_ctv_hash, OP_CHECKTEMPLATEVERIFY,
                script.OP_ENDIF,
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
        return p2wpkh_tx_template(
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
        witness = CScriptWitness([b"", self.unvault_redeemScript])
        tx.wit = CTxWitness([CTxInWitness(witness)])

        return CTransaction.from_tx(tx)

    @property
    def to_hot_tx_template(self) -> CMutableTransaction:
        return p2wpkh_tx_template(
            [BLANK_INPUT()],
            self.amount_at_step(3),
            pay_to_h160=self.hot_pubkey.hash160(),
            fee_mgmt_pay_to_h160=self.fees_pubkey.hash160(),
        )

    def to_hot_tx(
        self, unvault_outpoint: COutPoint, hot_priv: PrivateKey
    ) -> CTransaction:
        """
        Return a finalized, signed transaction moving the vault coins to the hot
        public key.
        """
        tx = self.to_hot_tx_template
        tx.vin = [CTxIn(unvault_outpoint, nSequence=self.block_delay)]

        sighash = script.SignatureHash(
            self.unvault_redeemScript,
            tx,
            0,
            script.SIGHASH_ALL,
            amount=self.amount_at_step(2),  # the prior step amount
            sigversion=script.SIGVERSION_WITNESS_V0,
        )
        sig = hot_priv.sign(int.from_bytes(sighash, "big")).der() + bytes(
            [script.SIGHASH_ALL]
        )
        witness = CScriptWitness([sig, b"\x01", self.unvault_redeemScript])
        tx.wit = CTxWitness([CTxInWitness(witness)])

        return CTransaction.from_tx(tx)


TxidStr = str


def make_color(start, end: str) -> t.Callable[[str], str]:
    def color_func(s: str) -> str:
        return start + t_(s) + end

    return color_func


def esc(*codes: t.Union[int, str]) -> str:
    """
    Produces an ANSI escape code from a list of integers
    """
    return t_("\x1b[{}m").format(t_(";").join(t_(str(c)) for c in codes))


def t_(b: t.Union[bytes, t.Any]) -> str:
    """ensure text type"""
    if isinstance(b, bytes):
        return b.decode()
    return b


FG_END = esc(39)
red = make_color(esc(31), FG_END)
green = make_color(esc(32), FG_END)
yellow = make_color(esc(33), FG_END)
blue = make_color(esc(34), FG_END)
cyan = make_color(esc(36), FG_END)
bold = make_color(esc(1), esc(22))


def no_output(*args, **kwargs):
    pass


@dataclass
class VaultExecutor:
    plan: VaultPlan
    rpc: BitcoinRPC

    vault_outpoint: t.Optional[COutPoint] = None
    unvault_outpoint: t.Optional[COutPoint] = None

    log: t.Callable = no_output

    def send_to_vault(self, coin: Coin, spend_key: PrivateKey) -> TxidStr:
        spend_addr = CBech32BitcoinAddress.from_scriptPubKey(CScript(coin.scriptPubKey))
        self.log(bold("\n# Sending to vault\n"))

        self.log(f"Spending coin ({spend_addr})\n  {coin}\ninto vault")
        (tx, hx) = self._print_planned_tx(
            self.plan.to_vault_tx, spend_addr, coin.outpoint, spend_key
        )

        txid = self.rpc.sendrawtransaction(hx)
        assert txid == tx.GetTxid()[::-1].hex()
        self.vault_outpoint = COutPoint(txid_to_bytes(txid), 0)

        self.log("Coins are vaulted!")
        self.log(f"Txid accepted: {self.vault_outpoint}")
        self.log(f"Scan for the vault scriptpubkey: {tx.vout[0].scriptPubKey.hex()}")
        self.log(
            f"Scan for the unvault scriptpubkey: {self.plan.unvault_tx_template.vout[0].scriptPubKey.hex()}"
        )
        return txid

    def start_unvault(self) -> TxidStr:
        assert self.vault_outpoint
        self.log(bold("\n# Starting unvault\n"))

        _, hx = self._print_planned_tx(self.plan.unvault_tx, self.vault_outpoint)
        txid = self.rpc.sendrawtransaction(hx)
        self.unvault_outpoint = COutPoint(txid_to_bytes(txid), 0)
        return txid

    def get_unvault_tx(self) -> CTransaction:
        assert self.vault_outpoint
        tx = self.plan.unvault_tx(self.vault_outpoint)
        self.unvault_outpoint = COutPoint(tx.GetTxid(), 0)
        return tx

    def get_to_cold_tx(self) -> CTransaction:
        assert self.unvault_outpoint
        cold_addr = self.plan.cold_pubkey.p2wpkh_address(self.rpc.net_name)
        self.log(bold(f"\n# Sweep to cold ({cold_addr})\n"))

        (tx, _) = self._print_planned_tx(self.plan.to_cold_tx, self.unvault_outpoint)
        return tx

    def get_to_hot_tx(self, hot_privkey) -> CTransaction:
        assert self.unvault_outpoint
        hot_addr = self.plan.hot_pubkey.p2wpkh_address(self.rpc.net_name)
        self.log(bold(f"\n\n# Sweep to hot ({hot_addr})"))

        (tx, _) = self._print_planned_tx(
            self.plan.to_hot_tx, self.unvault_outpoint, hot_privkey
        )
        return tx

    def search_for_unvault(self) -> t.Optional[str]:
        """
        Return the location of the unvault transaction, if one exists.

        This can be used for alerting on unexpected unvaulting attempts.
        """
        assert self.vault_outpoint
        unvault_tx = self.plan.unvault_tx(self.vault_outpoint)
        unvault_txid = unvault_tx.GetHash()[::-1].hex()

        mempool_txids = self.rpc.getrawmempool(False)

        if unvault_txid in mempool_txids:
            self.log("Unvault transaction detected in mempool")
            return "mempool"

        confirmed_txout = self.rpc.gettxout(unvault_txid, 0, False)
        if confirmed_txout:
            self.log(f"Unvault transaction confirmed: {confirmed_txout}")
            return "chain"

        return None

    def _print_planned_tx(
        self, plan_final_txn_fnc, *args, **kwargs
    ) -> t.Tuple[CTransaction, RawTxStr]:
        """Plan a finalized transaction and print its broadcast information."""
        tx = plan_final_txn_fnc(*args, **kwargs)
        hx = tx.serialize().hex()
        self.log(f"\nTransaction {yellow(tx.GetTxid()[::-1].hex())}")
        self.log(f"\n{tx}\n")
        self.log(f"Raw hex:\n{hx}")
        return tx, hx


def generateblocks(rpc: BitcoinRPC, n: int = 1, addr: str = None):
    if not addr:
        addr = (
            HDPrivateKey.from_seed(b"yaddayah")
            .get_private_key(1)
            .point.p2wpkh_address(network=rpc.net_name)
        )
    return rpc.generatetoaddress(n, addr)


def p2wpkh_tx_template(
    vin: t.List[CTxIn], nValue: int, pay_to_h160: bytes, fee_mgmt_pay_to_h160: bytes
) -> CMutableTransaction:
    """Create a transaction template paying into a P2WPKH."""
    pay_to_script = CScript([script.OP_0, pay_to_h160])
    assert pay_to_script.is_witness_v0_keyhash()

    pay_to_fee_script = CScript([script.OP_0, fee_mgmt_pay_to_h160])
    assert pay_to_fee_script.is_witness_v0_keyhash()
    HOPEFULLY_NOT_DUST: Sats = 550   # obviously TOOD?

    tx = CMutableTransaction()
    tx.nVersion = 2
    tx.vin = vin
    tx.vout = [
        CTxOut(nValue, pay_to_script),
        # Anchor output for CPFP-based fee bumps
        CTxOut(HOPEFULLY_NOT_DUST, pay_to_fee_script),
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
    vin = tx.vin or []
    vout = tx.vout or []
    if any(inp.scriptSig for inp in vin):
        r += sha256(b"".join(ser_string(inp.scriptSig) for inp in vin))
    r += struct.pack("<I", len(tx.vin))
    r += sha256(b"".join(struct.pack("<I", inp.nSequence) for inp in vin))
    r += struct.pack("<I", len(tx.vout))
    r += sha256(b"".join(out.serialize() for out in vout))
    r += struct.pack("<I", nIn)
    return sha256(r)


def txid_to_bytes(txid: str) -> bytes:
    """Convert the txids output by Bitcoin Core (little endian) to bytes."""
    return bytes.fromhex(txid)[::-1]


def scan_utxos(rpc, addr):
    return rpc.scantxoutset("start", [f"addr({addr})"])


@cli.main
def main():
    network = "regtest"
    SelectParams(network)

    rpc = BitcoinRPC(net_name=network)
    fee_wallet = Wallet.generate(b"fee")
    balance_wallet = Wallet.generate(b"balance")
    cold_wallet = Wallet.generate(b"cold")
    hot_wallet = Wallet.generate(b"hot")

    if rpc.getblockchaininfo()["blocks"] >= 150:
        print("Your regtest is out of subsidy - please wipe the datadir and restart.")
        sys.exit(1)

    balance_wallet.fund(rpc)
    coin = balance_wallet.fund(rpc)
    plan = VaultPlan(
        hot_wallet.privkey.point,
        cold_wallet.privkey.point,
        fee_wallet.privkey.point,
        coin.amount,
        block_delay=10,
    )
    exec = VaultExecutor(plan, rpc, log=print)
    exec.send_to_vault(coin, balance_wallet.privkey)
    assert not exec.search_for_unvault()

    exec.start_unvault()
    assert exec.search_for_unvault() == "mempool"

    exec.get_to_cold_tx()
    exec.get_to_hot_tx(hot_wallet.privkey)


if __name__ == "__main__":
    cli.run()
