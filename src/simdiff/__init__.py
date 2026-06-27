"""simdiff — the effect layer for AI-agent firewalls.

Simulate an action through a domain adapter and get back a canonical, structured
*effect delta* describing what would actually change. simdiff produces the delta;
your policy engine / firewall decides on it.
"""

from __future__ import annotations

from typing import Any, Optional

from .delta import (
    AuthorityGrant,
    CanonicalDelta,
    DataAccess,
    ResourceUse,
    ValueMove,
)

__all__ = [
    "simdiff",
    "CanonicalDelta",
    "ValueMove",
    "AuthorityGrant",
    "DataAccess",
    "ResourceUse",
]

__version__ = "0.2.1"


def simdiff(action: Any, adapter: Any, *, principal: Optional[str] = None) -> CanonicalDelta:
    """Run ``action`` through ``adapter`` and return its canonical effect delta.

    Depending on the adapter this either simulates the action (filesystem, sql,
    solana) or conservatively interprets it (shell, http). The returned delta's
    ``fully_classified`` flag reports whether the effect was understood — it is
    not a safety verdict. See SECURITY.md.
    """
    effect = adapter.simulate(action)
    return adapter.extract_delta(effect, principal)
