import json
from pathlib import Path

import pytest
from bitcoin.core import CTransaction, COIN

from rpc import JSONRPCError
from main import (
    VaultContext,
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
    c = VaultContext.from_network("regtest", seed=b"functest", block_delay=block_delay)
    exec = c.exec
    plan = c.plan
    rpc = c.rpc
    coin = c.coin_in

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

    vaulted_txid = exec.send_to_vault(coin, c.from_wallet.privkey)
    assert not exec.search_for_unvault()

    check_amount(vaulted_txid, 0, expected_amount_per_step[1])

    tocold_tx = exec.get_tocold_tx()
    tocold_hex = tocold_tx.serialize().hex()

    tohot_tx = exec.get_tohot_tx(c.hot_wallet.privkey)
    tohot_hex = tohot_tx.serialize().hex()

    # Shouldn't be able to send particular unvault txs yet.
    with pytest.raises(JSONRPCError):
        rpc.sendrawtransaction(tocold_hex)

    with pytest.raises(JSONRPCError):
        rpc.sendrawtransaction(tohot_hex)

    unvaulted_txid = exec.start_unvault()

    assert exec.search_for_unvault() == "mempool"
    check_amount(unvaulted_txid, 0, expected_amount_per_step[2])
    check_amount(vaulted_txid, 0, 0)

    with pytest.raises(JSONRPCError):
        # to-hot should fail due to OP_CSV
        rpc.sendrawtransaction(tohot_hex)

    # Unvault tx confirms
    generateblocks(rpc, 1)
    assert exec.search_for_unvault() == "chain"

    with pytest.raises(JSONRPCError):
        # to-hot should *still* fail due to OP_CSV
        rpc.sendrawtransaction(tohot_hex)

    if ends_in_hot:
        # Mine enough blocks to allow the to-hot to be valid, send it.
        generateblocks(rpc, block_delay - 1)

        txid = rpc.sendrawtransaction(tohot_hex)
        assert txid == tohot_tx.GetTxid()[::-1].hex()
    else:
        # "Sweep" the funds to the cold wallet because this is an unvaulting
        # we didn't expect.
        txid = rpc.sendrawtransaction(tocold_hex)
        assert txid == tocold_tx.GetTxid()[::-1].hex()

    generateblocks(rpc, 1)
    txout = rpc.gettxout(txid, 0)
    assert txout["confirmations"] == 1
    check_amount(txid, 0, expected_amount_per_step[3])
    check_amount(vaulted_txid, 0, 0)
    check_amount(unvaulted_txid, 0, 0)

    anchor_txout = rpc.gettxout(txid, 1)
    print(anchor_txout)
    fees_addr = plan.fees_pubkey.p2wpkh_address(rpc.net_name)
    assert anchor_txout['value'] > 0
    assert anchor_txout['scriptPubKey']['address'] == fees_addr


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
