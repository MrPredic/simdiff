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

__version__ = "0.2.0"


def simdiff(action: Any, adapter: Any, *, principal: Optional[str] = None) -> CanonicalDelta:
    """Simulate ``action`` with ``adapter`` and return its canonical effect delta."""
    effect = adapter.simulate(action)
    return adapter.extract_delta(effect, principal)
