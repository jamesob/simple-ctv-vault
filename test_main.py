import random
import json
import hashlib
from pathlib import Path

import pytest
from bitcoin import SelectParams
from bitcoin.core import CTransaction, COIN

from rpc import BitcoinRPC, JSONRPCError
from main import (
    Wallet,
    VaultPlan,
    VaultExecutor,
    generateblocks,
    get_standard_template_hash,
)


def test_functional():
    """Run functional test. Requires bitcoind -regtest running."""
    _run_functional_test(ends_in_hot=True)
    _run_functional_test(ends_in_hot=False)


def _run_functional_test(ends_in_hot=True):
    """
    Exercise the full lifecycle of a vault.

    Args:
        ends_in_hot: if true, the to-hot unvault txn is ultimately confirmed. Otherwise
            we preempt and sweep to cold.
    """
    block_delay = 3
    network = "regtest"
    SelectParams(network)

    rpc = BitcoinRPC(net_name=network)
    fee_wallet = Wallet.generate(b"fee-functest")
    balance_wallet = Wallet.generate(b"balance-functest")
    cold_wallet = Wallet.generate(b"cold-functest")
    hot_wallet = Wallet.generate(b"hot-functest")

    balance_wallet.fund(rpc)
    coin = balance_wallet.fund(rpc)

    plan = VaultPlan(
        hot_wallet.privkey.point,
        cold_wallet.privkey.point,
        fee_wallet.privkey.point,
        coin.amount,
        block_delay=block_delay,
    )
    exec = VaultExecutor(plan, rpc)

    initial_amount = coin.amount
    expected_amount_per_step = [
        initial_amount,  # before vaulting
        initial_amount - (plan.fees_per_step * 1),  # step 1: vaulted output
        initial_amount - (plan.fees_per_step * 2),  # step 2: unvaulted output
        initial_amount - (plan.fees_per_step * 3),  # step 3: spent to hot or cold
    ]

    def check_amount(txid, n, expected_amount):
        got_amt = (rpc.gettxout(txid, n) or {}).get('value', 0)
        assert int(got_amt * COIN) == expected_amount

    vaulted_txid = exec.send_to_vault(coin, balance_wallet.privkey)
    assert not exec.search_for_unvault()

    check_amount(vaulted_txid, 0, expected_amount_per_step[1])

    exec.get_unvault_tx()

    to_cold_tx = exec.get_to_cold_tx()
    to_cold_hex = to_cold_tx.serialize().hex()

    to_hot_tx = exec.get_to_hot_tx(hot_wallet.privkey)
    to_hot_hex = to_hot_tx.serialize().hex()

    # Shouldn't be able to send particular unvault txs yet.
    with pytest.raises(JSONRPCError):
        rpc.sendrawtransaction(to_cold_hex)

    with pytest.raises(JSONRPCError):
        rpc.sendrawtransaction(to_hot_hex)

    unvaulted_txid = exec.start_unvault()

    assert exec.search_for_unvault() == "mempool"
    check_amount(unvaulted_txid, 0, expected_amount_per_step[2])
    check_amount(vaulted_txid, 0, 0)

    with pytest.raises(JSONRPCError):
        # to-hot should fail due to OP_CSV
        rpc.sendrawtransaction(to_hot_hex)

    # Unvault tx confirms
    generateblocks(rpc, 1)
    assert exec.search_for_unvault() == "chain"

    with pytest.raises(JSONRPCError):
        # to-hot should *still* fail due to OP_CSV
        rpc.sendrawtransaction(to_hot_hex)

    if ends_in_hot:
        # Mine enough blocks to allow the to-hot to be valid, send it.
        generateblocks(rpc, block_delay - 1)

        txid = rpc.sendrawtransaction(to_hot_hex)
        assert txid == to_hot_tx.GetTxid()[::-1].hex()
    else:
        # "Sweep" the funds to the cold wallet because this is an unvaulting
        # we didn't expect.
        txid = rpc.sendrawtransaction(to_cold_hex)
        assert txid == to_cold_tx.GetTxid()[::-1].hex()

    generateblocks(rpc, 1)
    txout = rpc.gettxout(txid, 0)
    assert txout["confirmations"] == 1
    check_amount(txid, 0, expected_amount_per_step[3])
    check_amount(vaulted_txid, 0, 0)
    check_amount(unvaulted_txid, 0, 0)


def test_ctv_hash():
    data = json.loads(Path("ctvhash-test-vectors.json").read_bytes())[1:-1]
    tests = 0

    for case in data:
        tx = CTransaction.deserialize(bytearray.fromhex(case["hex_tx"]))

        for idx, res in zip(case["spend_index"], case["result"]):
            assert get_standard_template_hash(tx, idx).hex() == res
            tests += 1

    print(tests)
    assert tests > 0
