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
    def safe(self) -> bool:
        """Fail-closed: unclassifiable effects make the delta unsafe."""
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
            "safe": self.safe,
        }
