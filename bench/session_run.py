"""Run the multi-step corpus through the cumulative session firewall and, as a
baseline, through the *same* effect engine deciding one call at a time.

    python -m bench.session_run

The point this benchmark makes is structural, not incremental: a per-call policy
permissive enough to let the agent do its legitimate work (read a file, delete a
scratch file, send one request) allows *every* step of these attacks — the danger
lives in the accumulated composition, which single-call checks cannot see. The
session layer decides over the running effect and catches it at zero false
positives.

The metrics are asserted in tests/test_session_benchmark.py, so the README
headline can never drift from what the code actually does.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from simdiff.adapters.http import HttpAdapter, HttpRequest
from simdiff.adapters.shell import ShellAdapter
from simdiff.guard import Decision, Guard
from simdiff.session import Session

from .session_corpus import ALLOWED_HOSTS, CASES, SCRATCH, SECRETS, SessionCase

# Everything the agent could legitimately read or remove already exists on disk;
# the ShellAdapter needs this to model `cp <secret>` as a read and `rm <scratch>`
# as a delete rather than a no-op.
_EXISTING = SECRETS | SCRATCH


def _permissive(delta) -> Decision:
    """A realistic per-call policy: allow any single, fully-understood action so
    the agent can actually do its job; fail closed only on the genuinely
    unmodelled. This is the policy an operator *must* run to stay usable — and it
    is exactly what a multi-step attack is built to walk straight through."""
    return Decision.ALLOW if delta.fully_classified else Decision.BLOCK


def _build_guard() -> Guard:
    return Guard(
        {
            "shell": lambda a: (a["command"], ShellAdapter(existing=_EXISTING)),
            "http": lambda a: (
                HttpRequest(a["method"], a["url"], body=a.get("body", "")),
                HttpAdapter(allowed_hosts=ALLOWED_HOSTS),
            ),
        },
        policy=_permissive,
    )


def _session_flag(case: SessionCase) -> bool:
    """The session flags a case if any step, judged over the accumulated effect,
    is not an outright ALLOW."""
    session = Session(_build_guard())
    for tool, args in case.steps:
        if session.step(tool, args).decision is not Decision.ALLOW:
            return True
    return False


def _percall_flag(case: SessionCase) -> bool:
    """Baseline: the same effect engine, but each call judged in isolation."""
    guard = _build_guard()
    for tool, args in case.steps:
        if guard.evaluate(tool, args).decision is not Decision.ALLOW:
            return True
    return False


def _score(predictions: List[Tuple[bool, str]]) -> Dict[str, float]:
    attacks = [p for p, label in predictions if label == "attack"]
    benign = [p for p, label in predictions if label == "benign"]
    return {
        "recall": sum(1 for p in attacks if p) / len(attacks),
        "false_positive_rate": sum(1 for p in benign if p) / len(benign),
    }


def run() -> Dict:
    session_pred, percall_pred = [], []
    for case in CASES:
        session_pred.append((_session_flag(case), case.label))
        percall_pred.append((_percall_flag(case), case.label))
    return {
        "session": _score(session_pred),
        "per_call": _score(percall_pred),
        "counts": {
            "attack": sum(1 for c in CASES if c.label == "attack"),
            "benign": sum(1 for c in CASES if c.label == "benign"),
            "total": len(CASES),
        },
    }


def main() -> None:
    m = run()
    print(
        f"multi-step corpus: {m['counts']['total']} sessions "
        f"({m['counts']['attack']} attack, {m['counts']['benign']} benign)\n"
    )
    print(f"{'approach':<34}{'recall':>10}{'false positives':>18}")
    print("-" * 62)
    for name, key in [
        ("cumulative session firewall", "session"),
        ("per-call effect check (baseline)", "per_call"),
    ]:
        s = m[key]
        print(f"{name:<34}{s['recall']*100:>9.0f}%{s['false_positive_rate']*100:>17.0f}%")
    print()
    print("Per-session (technique -> caught by session / by per-call):")
    for case in CASES:
        se, pc = _session_flag(case), _percall_flag(case)
        mark = lambda b: "✓" if b else "·"  # noqa: E731
        flag = "!" if case.label == "attack" else " "
        print(f"  {flag} {case.id:<26} session:{mark(se)} per-call:{mark(pc)}  {case.technique}")


if __name__ == "__main__":
    main()
