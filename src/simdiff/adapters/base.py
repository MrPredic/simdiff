"""Adapter protocol and the `Effect` an adapter produces.

An adapter holds its own domain context (a sandbox dir, a DB connection, a
filesystem snapshot) and exposes two steps:

    simulate(action)            -> Effect      # dry-run, never mutates the target
    extract_delta(effect, principal) -> CanonicalDelta

`Effect` is deliberately opaque: each adapter chooses its own representation.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

from ..delta import CanonicalDelta

Effect = Any


@runtime_checkable
class Adapter(Protocol):
    domain: str

    def simulate(self, action: Any) -> Effect: ...

    def extract_delta(self, effect: Effect, principal: Optional[str] = None) -> CanonicalDelta: ...
