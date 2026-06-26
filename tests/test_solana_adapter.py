import base64
import struct

from simdiff import simdiff
from simdiff.adapters.solana import SolanaAdapter, SolanaTransaction

TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


def spl_account(amount, owner=b"\x02" * 32, mint=b"\x01" * 32, delegate=None):
    b = bytearray(165)
    b[0:32] = mint
    b[32:64] = owner
    struct.pack_into("<Q", b, 64, amount)
    if delegate is not None:
        struct.pack_into("<I", b, 72, 1)
        b[76:108] = delegate
    b[108] = 1  # initialized
    return [base64.b64encode(bytes(b)).decode(), "base64"]


def fake_rpc(pre_accounts, sim_value):
    """Build an injectable rpc returning canned getMultipleAccounts + simulate."""
    def rpc(method, params):
        if method == "getMultipleAccounts":
            return {"value": pre_accounts}
        if method == "simulateTransaction":
            return {"value": sim_value}
        raise AssertionError(method)
    return rpc


def test_sol_outflow_is_value_move():
    pre = [{"lamports": 5_000_000_000, "data": ["", "base64"]}]
    sim = {"err": None, "accounts": [{"lamports": 0, "data": ["", "base64"]}]}
    adapter = SolanaAdapter(rpc=fake_rpc(pre, sim))
    delta = simdiff(SolanaTransaction(transaction_b64="AA==", watch=["WALLET"]), adapter)
    assert delta.safe is True
    assert len(delta.value_moves) == 1
    vm = delta.value_moves[0]
    assert vm.asset == "SOL"
    assert vm.amount == 5.0
    assert vm.src == "WALLET"


def test_token_amount_drained_is_value_move():
    pre = [{"lamports": 2_000_000, "data": spl_account(1000)}]
    sim = {"err": None, "accounts": [{"lamports": 2_000_000, "data": spl_account(0)}]}
    adapter = SolanaAdapter(rpc=fake_rpc(pre, sim))
    delta = simdiff(SolanaTransaction("AA==", ["TOKENACC"]), adapter)
    moves = [m for m in delta.value_moves if m.asset.startswith("SPL")]
    assert moves[0].amount == 1000


def test_new_permanent_delegate_is_authority_grant():
    pre = [{"lamports": 2_000_000, "data": spl_account(1000, delegate=None)}]
    after = spl_account(1000, delegate=b"\x09" * 32)
    sim = {"err": None, "accounts": [{"lamports": 2_000_000, "data": after}]}
    adapter = SolanaAdapter(rpc=fake_rpc(pre, sim))
    delta = simdiff(SolanaTransaction("AA==", ["TOKENACC"]), adapter)
    grants = [g for g in delta.authority_grants if g.kind == "delegate"]
    assert len(grants) == 1
    assert grants[0].old == "none"
    assert grants[0].new != "none"


def test_simulation_error_is_fail_closed():
    pre = [{"lamports": 1, "data": ["", "base64"]}]
    sim = {"err": {"InstructionError": [0, "Custom"]}, "accounts": None}
    adapter = SolanaAdapter(rpc=fake_rpc(pre, sim))
    delta = simdiff(SolanaTransaction("AA==", ["WALLET"]), adapter)
    assert delta.safe is False
    assert any("simulation" in u.lower() for u in delta.unknown)


def test_rpc_failure_is_fail_closed():
    def rpc(method, params):
        raise ConnectionError("node unreachable")

    adapter = SolanaAdapter(rpc=rpc)
    delta = simdiff(SolanaTransaction("AA==", ["WALLET"]), adapter)
    assert delta.safe is False
    assert delta.unknown


def test_no_change_is_empty_safe_delta():
    pre = [{"lamports": 1_000_000_000, "data": ["", "base64"]}]
    sim = {"err": None, "accounts": [{"lamports": 1_000_000_000, "data": ["", "base64"]}]}
    adapter = SolanaAdapter(rpc=fake_rpc(pre, sim))
    delta = simdiff(SolanaTransaction("AA==", ["WALLET"]), adapter)
    assert delta.safe is True
    assert delta.value_moves == []
    assert delta.authority_grants == []
