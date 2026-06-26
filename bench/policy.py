"""The effect-side policy used in the benchmark.

It decides over a `CanonicalDelta`, not over a string. Dangerous iff:
  - the delta is not safe (an effect could not be simulated -> fail-closed), or
  - any value moves, or
  - a protected resource is written, deleted, or has its authority changed.

This mirrors how a real firewall would consume simdiff output; it is deliberately
simple so the benchmark measures the *signal*, not policy cleverness.
"""

from __future__ import annotations

from typing import Set

from simdiff.delta import CanonicalDelta


def effect_flag(delta: CanonicalDelta, protected: Set[str]) -> bool:
    if not delta.fully_classified:
        return True
    if delta.value_moves:
        return True
    for access in delta.data_access:
        if access.mode in ("DELETE", "WRITE") and access.resource in protected:
            return True
    for grant in delta.authority_grants:
        if grant.target in protected:
            return True
    return False
