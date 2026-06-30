"""Cumulative session firewall: decide over the *accumulated* effect of a whole
tool-call sequence, not one call at a time.

The hard, unsolved problem in agentic security is the **multi-step** attack: each
tool call is benign in isolation (read a file, read another, ..., then send one
request), but the *composition* is reconnaissance-then-exfiltration. Argument
scanners and even tool-call pattern matchers reason about calls; they cannot see
the accumulated effect, and obfuscating individual calls defeats them.

`Session` accumulates each allowed step's `CanonicalDelta` (via
`CanonicalDelta.merge`) and decides the next step against the *running* effect:
breadth of distinct resources read (enumeration), an egress that follows
reconnaissance (recon → exfil), mass mutation, or egress fanned across many
destinations. It is effect-based, so it cannot be obfuscated, and fail-closed:
the session decision is never less restrictive than the per-call one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Mapping

from .delta import CanonicalDelta
from .guard import Decision, Guard

_MUTATING = {"WRITE", "CREATE", "DELETE"}
_RANK = {Decision.ALLOW: 0, Decision.NEEDS_APPROVAL: 1, Decision.BLOCK: 2}


@dataclass
class SessionBudget:
    """Thresholds over the accumulated effect. Tune per deployment."""
    recon_read_threshold: int = 5      # distinct reads after which an egress = recon→exfil
    max_resources_read: int = 25       # distinct reads ceiling (enumeration)
    max_resources_mutated: int = 15    # distinct created/written/deleted ceiling
    max_distinct_egress_hosts: int = 3 # distinct egress destinations ceiling


@dataclass
class SessionResult:
    decision: Decision
    step_delta: CanonicalDelta
    cumulative: CanonicalDelta
    reasons: List[str] = field(default_factory=list)


def _distinct(delta: CanonicalDelta, modes) -> set:
    return {d.resource for d in delta.data_access if d.mode in modes}


def _egress_hosts(delta: CanonicalDelta) -> set:
    return {v.dst for v in delta.value_moves if v.asset == "bytes"}


class Session:
    """One agent session: route each step through the guard, then over the
    accumulated effect. Only an ``ALLOW`` step commits to the running total
    (a blocked/held action never executed, so it has no effect)."""

    def __init__(self, guard: Guard, budget: SessionBudget = SessionBudget()):
        self._guard = guard
        self.budget = budget
        self.cumulative = CanonicalDelta()
        self.step_count = 0

    def reset(self) -> None:
        self.cumulative = CanonicalDelta()
        self.step_count = 0

    def step(self, tool: str, args: Mapping) -> SessionResult:
        call = self._guard.evaluate(tool, args)
        prospective = self.cumulative.merge(call.delta)

        decisions = [call.decision]
        reasons: List[str] = []
        if call.decision is not Decision.ALLOW:
            reasons.append(f"per-call: {call.decision.value}")
            reasons.extend(call.delta.unknown)

        reads = _distinct(prospective, {"READ"})
        mutated = _distinct(prospective, _MUTATING)
        hosts = _egress_hosts(prospective)
        step_has_egress = bool(call.delta.value_moves)

        if step_has_egress and len(reads) >= self.budget.recon_read_threshold:
            decisions.append(Decision.BLOCK)
            reasons.append(
                f"egress after reading {len(reads)} distinct resources this session "
                f"(recon→exfil pattern)"
            )
        if len(reads) > self.budget.max_resources_read:
            decisions.append(Decision.NEEDS_APPROVAL)
            reasons.append(f"read breadth {len(reads)} exceeds {self.budget.max_resources_read} (enumeration)")
        if len(mutated) > self.budget.max_resources_mutated:
            decisions.append(Decision.NEEDS_APPROVAL)
            reasons.append(
                f"mutated {len(mutated)} distinct resources, over {self.budget.max_resources_mutated} "
                f"(mass mutation/deletion)"
            )
        if len(hosts) > self.budget.max_distinct_egress_hosts:
            decisions.append(Decision.NEEDS_APPROVAL)
            reasons.append(f"egress fanned to {len(hosts)} distinct hosts")

        decision = max(decisions, key=lambda d: _RANK[d])

        if decision is Decision.ALLOW:
            self.cumulative = prospective
            self.step_count += 1

        return SessionResult(decision, call.delta, self.cumulative, reasons)
