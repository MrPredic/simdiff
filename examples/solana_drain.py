"""Catch a wallet-drain transaction that looks benign at the instruction level.

The transaction claims to be a routine token interaction, but its *simulated*
effect is: the token balance goes to zero AND a permanent delegate is assigned.
simdiff sees the effect, not the instruction names.

This demo injects a canned RPC response so it runs offline. In production you pass
a real endpoint instead:

    adapter = SolanaAdapter(rpc_url="https://api.mainnet-beta.solana.com")
    delta = simdiff(SolanaTransaction(tx_b64, watch=[my_token_account]), adapter)
"""

import base64
import struct

from simdiff import simdiff
from simdiff.adapters.solana import SolanaAdapter, SolanaTransaction


def token_account(amount, delegate=None):
    b = bytearray(165)
    b[0:32] = b"\x01" * 32          # mint
    b[32:64] = b"\x02" * 32         # owner
    struct.pack_into("<Q", b, 64, amount)
    if delegate is not None:
        struct.pack_into("<I", b, 72, 1)
        b[76:108] = delegate
    b[108] = 1
    return [base64.b64encode(bytes(b)).decode(), "base64"]


def mock_rpc(method, params):
    tp = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    if method == "getMultipleAccounts":
        return {"value": [{"lamports": 2_039_280, "owner": tp, "data": token_account(1_000_000, delegate=None)}]}
    if method == "simulateTransaction":
        # after simulation: balance drained AND a delegate installed
        return {"value": {"err": None, "accounts": [
            {"lamports": 2_039_280, "owner": tp, "data": token_account(0, delegate=b"\x09" * 32)}
        ]}}
    raise AssertionError(method)


if __name__ == "__main__":
    adapter = SolanaAdapter(rpc=mock_rpc)
    delta = simdiff(SolanaTransaction("<base64 tx>", watch=["MyTokenAccount1111111111111111111111111111"]), adapter)

    print("safe:", delta.fully_classified)
    for vm in delta.value_moves:
        print(f"  value  {vm.amount} {vm.asset}  {vm.src} -> {vm.dst}  ({vm.reason})")
    for g in delta.authority_grants:
        print(f"  auth   {g.kind}: {g.old} -> {g.new}  ({g.reason})")
    print("\nverdict: a policy that flags value moves or authority grants BLOCKS this.")
