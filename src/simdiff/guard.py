"""Optional reference guard: decide over an action's *effect* before it runs.

simdiff's core only produces the effect delta — it deliberately does not decide.
This module is a thin, dependency-free convenience for the common loop:

    simulate (simdiff) -> decide (policy) -> execute / block / escalate

It is opt-in (``from simdiff.guard import Guard``) and built to be replaced: pass
your own ``policy`` and your own per-tool ``builders``. Every failure path — an
unmodeled tool, a builder error, an adapter crash — resolves to ``BLOCK`` /
``unknown`` so the guard is fail-closed by construction. See
``examples/guard_tool_call.py`` and ``examples/mcp_guard_server.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Mapping, Tuple

from . import simdiff as _simdiff
from .delta import CanonicalDelta


class Decision(str, Enum):
    ALLOW = "ALLOW"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    BLOCK = "BLOCK"


def default_policy(delta: CanonicalDelta) -> Decision:
    """A conservative reference policy. Replace it with yours.

    Fail closed on anything not understood; never silently allow value movement or
    an authority/permission change; require approval for a delete.
    """
    if not delta.fully_classified:
        return Decision.BLOCK
    if delta.value_moves:
        if any("sensitive" in m.reason.lower() for m in delta.value_moves):
            return Decision.BLOCK
        return Decision.NEEDS_APPROVAL
    if delta.authority_grants:
        return Decision.NEEDS_APPROVAL
    if any(a.mode == "DELETE" for a in delta.data_access):
        return Decision.NEEDS_APPROVAL
    return Decision.ALLOW


@dataclass
class GuardResult:
    decision: Decision
    delta: CanonicalDelta


# A builder maps a tool call's arguments to the ``(action, adapter)`` pair simdiff
# needs. This is the only deployment-specific glue.
Builder = Callable[[Mapping[str, Any]], Tuple[Any, Any]]
Policy = Callable[[CanonicalDelta], Decision]


class Guard:
    """Route a tool call through its adapter and decide over the resulting effect."""

    def __init__(self, builders: Dict[str, Builder], policy: Policy = default_policy):
        self._builders = dict(builders)
        self._policy = policy

    def evaluate(self, tool: str, args: Mapping[str, Any]) -> GuardResult:
        builder = self._builders.get(tool)
        if builder is None:
            return GuardResult(
                Decision.BLOCK,
                CanonicalDelta(unknown=[f"no simdiff adapter for tool {tool!r}"]),
            )
        try:
            action, adapter = builder(args)
            delta = _simdiff(action, adapter)
        except Exception as exc:  # noqa: BLE001 - glue errors must fail closed
            return GuardResult(
                Decision.BLOCK,
                CanonicalDelta(unknown=[f"guard build error for {tool!r}: {type(exc).__name__}: {exc}"]),
            )
        return GuardResult(self._policy(delta), delta)
