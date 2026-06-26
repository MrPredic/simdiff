"""Solana adapter: simulate a transaction on-chain and extract its real effect.

This is the one adapter that is **not** offline: there is no local way to know
what a Solana transaction would do — only a node knows. It calls the RPC
``simulateTransaction`` (which executes the transaction against current chain
state without broadcasting it) plus ``getMultipleAccounts`` for the pre-state,
then diffs the watched accounts.

Why it matters: a transaction can look like "swap 5 USDC" while its real effect
is "assign a permanent delegate that drains the whole token account". Argument or
instruction inspection misses that; simulation does not.

The RPC call is injectable (``rpc=``) so the effect logic is tested deterministically
offline. The default talks to ``rpc_url`` with the standard library only (no
``solana-py`` dependency); network is used solely at call time.
"""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib import request

from ..delta import AuthorityGrant, CanonicalDelta, ValueMove

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_LAMPORTS_PER_SOL = 1_000_000_000
_TOKEN_ACCOUNT_LEN = 165


def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


@dataclass
class SolanaTransaction:
    transaction_b64: str
    watch: List[str] = field(default_factory=list)  # account addresses to track


@dataclass
class _SolEffect:
    watch: List[str]
    pre: Optional[list] = None
    post: Optional[list] = None
    sim_err: object = None
    error: Optional[str] = None


def _default_rpc(rpc_url: str) -> Callable[[str, list], dict]:
    def rpc(method: str, params: list) -> dict:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
        with request.urlopen(req, timeout=10) as resp:  # noqa: S310 - user-supplied trusted RPC
            body = json.loads(resp.read())
        if "error" in body:
            raise RuntimeError(f"rpc error: {body['error']}")
        return body["result"]

    return rpc


class SolanaAdapter:
    domain = "solana"

    def __init__(self, rpc_url: Optional[str] = None, rpc: Optional[Callable[[str, list], dict]] = None):
        if rpc is None and rpc_url is None:
            raise ValueError("SolanaAdapter needs an rpc_url or an injected rpc callable")
        self._rpc = rpc or _default_rpc(rpc_url)  # type: ignore[arg-type]

    def simulate(self, action: SolanaTransaction) -> _SolEffect:
        try:
            pre = self._rpc("getMultipleAccounts", [action.watch, {"encoding": "base64"}])
            sim = self._rpc(
                "simulateTransaction",
                [
                    action.transaction_b64,
                    {
                        "sigVerify": False,
                        "replaceRecentBlockhash": True,
                        "encoding": "base64",
                        "accounts": {"encoding": "base64", "addresses": action.watch},
                    },
                ],
            )
        except Exception as exc:  # noqa: BLE001 - fail-closed on transport/RPC error
            return _SolEffect(watch=action.watch, error=f"{type(exc).__name__}: {exc}")

        return _SolEffect(
            watch=action.watch,
            pre=pre.get("value"),
            post=(sim.get("value") or {}).get("accounts"),
            sim_err=(sim.get("value") or {}).get("err"),
        )

    def extract_delta(self, effect: _SolEffect, principal: Optional[str] = None) -> CanonicalDelta:
        if effect.error is not None:
            return CanonicalDelta(unknown=[f"solana RPC unavailable: {effect.error}"])
        if effect.sim_err is not None:
            return CanonicalDelta(unknown=[f"transaction simulation failed: {effect.sim_err}"])
        if effect.pre is None or effect.post is None:
            return CanonicalDelta(unknown=["simulation returned no account state to compare"])

        delta = CanonicalDelta()
        for addr, pre_acc, post_acc in zip(effect.watch, effect.pre, effect.post):
            self._diff_account(addr, pre_acc, post_acc, delta)
        return delta

    # --- internals -------------------------------------------------------

    @staticmethod
    def _data_bytes(acc: dict) -> bytes:
        data = (acc or {}).get("data") or ["", "base64"]
        return base64.b64decode(data[0]) if data[0] else b""

    def _diff_account(self, addr: str, pre_acc: dict, post_acc: dict, delta: CanonicalDelta) -> None:
        if pre_acc is None or post_acc is None:
            delta.unknown.append(f"account {addr} missing from simulation result")
            return

        # native SOL
        d_lamports = (pre_acc.get("lamports", 0)) - (post_acc.get("lamports", 0))
        if d_lamports > 0:
            delta.value_moves.append(
                ValueMove(asset="SOL", src=addr, dst="(outflow)", amount=d_lamports / _LAMPORTS_PER_SOL,
                          reason=f"{d_lamports} lamports leave {addr}")
            )
        elif d_lamports < 0:
            delta.value_moves.append(
                ValueMove(asset="SOL", src="(inflow)", dst=addr, amount=-d_lamports / _LAMPORTS_PER_SOL,
                          reason=f"{-d_lamports} lamports enter {addr}")
            )

        pre_d, post_d = self._data_bytes(pre_acc), self._data_bytes(post_acc)
        if len(pre_d) >= _TOKEN_ACCOUNT_LEN and len(post_d) >= _TOKEN_ACCOUNT_LEN:
            self._diff_token_account(addr, pre_d, post_d, delta)

    @staticmethod
    def _diff_token_account(addr: str, pre: bytes, post: bytes, delta: CanonicalDelta) -> None:
        mint = _b58encode(pre[0:32])
        pre_amt = struct.unpack_from("<Q", pre, 64)[0]
        post_amt = struct.unpack_from("<Q", post, 64)[0]
        if pre_amt > post_amt:
            delta.value_moves.append(
                ValueMove(asset=f"SPL:{mint}", src=addr, dst="(outflow)", amount=float(pre_amt - post_amt),
                          reason="token balance decreases")
            )
        elif post_amt > pre_amt:
            delta.value_moves.append(
                ValueMove(asset=f"SPL:{mint}", src="(inflow)", dst=addr, amount=float(post_amt - pre_amt),
                          reason="token balance increases")
            )

        def delegate(d: bytes) -> str:
            has = struct.unpack_from("<I", d, 72)[0]
            return _b58encode(d[76:108]) if has == 1 else "none"

        pre_del, post_del = delegate(pre), delegate(post)
        if pre_del != post_del:
            delta.authority_grants.append(
                AuthorityGrant(target=addr, kind="delegate", old=pre_del, new=post_del,
                               reason="token account delegate changes (drain risk)")
            )

        pre_owner, post_owner = _b58encode(pre[32:64]), _b58encode(post[32:64])
        if pre_owner != post_owner:
            delta.authority_grants.append(
                AuthorityGrant(target=addr, kind="owner", old=pre_owner, new=post_owner,
                               reason="token account owner reassigned (takeover)")
            )
