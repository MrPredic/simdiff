"""Canonical, domain-agnostic model of an action's effect.

`simdiff` adapters simulate an action and express its effect as a
`CanonicalDelta`. Consumers (policy engines, agent firewalls) decide on the
delta; simdiff never decides.

The delta is **fail-closed**: anything an adapter cannot classify goes into
`unknown`, and any non-empty `unknown` makes the whole delta `unsafe`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List


@dataclass
class ValueMove:
    """A transfer of some asset (money, tokens, credits)."""

    asset: str
    src: str
    dst: str
    amount: float
    reason: str = ""


@dataclass
class AuthorityGrant:
    """A change to a permission / owner / mode on a resource."""

    target: str
    kind: str  # e.g. "mode", "owner", "delegate", "approve"
    old: str
    new: str
    reason: str = ""


@dataclass
class DataAccess:
    """A read/write/create/delete touching a resource."""

    resource: str
    mode: str  # CREATE | WRITE | DELETE | READ
    bytes: int = 0
    reason: str = ""


@dataclass
class ResourceUse:
    """Coarse resource-consumption estimate."""

    io_bytes: int = 0
    rows: int = 0


@dataclass
class CanonicalDelta:
    value_moves: List[ValueMove] = field(default_factory=list)
    authority_grants: List[AuthorityGrant] = field(default_factory=list)
    data_access: List[DataAccess] = field(default_factory=list)
    resource_use: ResourceUse = field(default_factory=ResourceUse)
    unknown: List[str] = field(default_factory=list)

    @property
    def fully_classified(self) -> bool:
        """True iff every part of the effect was understood (``unknown`` is empty).

        IMPORTANT: this is NOT a safety verdict. ``fully_classified is True`` only
        means simdiff could account for the whole effect — the effect itself may be
        a destructive ``DELETE`` or an exfil. Deciding whether the effect is
        *allowed* is the consumer's job. Treat ``fully_classified is False`` as
        fail-closed (escalate / block), never as "safe".
        """
        return not self.unknown

    def merge(self, other: "CanonicalDelta") -> "CanonicalDelta":
        """Combine two deltas (e.g. a batch of actions)."""
        return CanonicalDelta(
            value_moves=self.value_moves + other.value_moves,
            authority_grants=self.authority_grants + other.authority_grants,
            data_access=self.data_access + other.data_access,
            resource_use=ResourceUse(
                io_bytes=self.resource_use.io_bytes + other.resource_use.io_bytes,
                rows=self.resource_use.rows + other.resource_use.rows,
            ),
            unknown=self.unknown + other.unknown,
        )

    def to_dict(self) -> dict:
        return {
            "value_moves": [asdict(v) for v in self.value_moves],
            "authority_grants": [asdict(a) for a in self.authority_grants],
            "data_access": [asdict(d) for d in self.data_access],
            "resource_use": asdict(self.resource_use),
            "unknown": list(self.unknown),
            "fully_classified": self.fully_classified,
        }
