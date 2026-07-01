"""Run a realistic (non-adversarial) command stream through the legacy and
current shell adapters and report the fail-closed ("needs approval") rate.

    python -m bench.realistic_shell_run

This is the benchmark for the caveat the README used to carry verbatim: *"on
real command streams the shell adapter fail-closes on most input, so
real-world FP is high, not zero."* It answers that with a number instead of a
guess, and separates the corpus into commands that *should* be fully
classified (inspection, mutation) from ones that structurally can't be
(opaque — arbitrary program effect) so the headline isn't inflated.

The metrics are asserted in tests/test_realistic_shell_benchmark.py, so the
README can never drift from what the code actually does.
"""

from __future__ import annotations

from typing import Dict, List

from simdiff import simdiff
from simdiff.adapters.shell import ShellAdapter

from .legacy_shell_adapter import LegacyShellAdapter
from .realistic_shell_corpus import CASES, RealisticCase


def _classified(case: RealisticCase, adapter_cls) -> bool:
    delta = simdiff(case.command, adapter_cls(existing=case.existing))
    return delta.fully_classified


def _rate(cases: List[RealisticCase], adapter_cls) -> float:
    if not cases:
        return 0.0
    return sum(1 for c in cases if _classified(c, adapter_cls)) / len(cases)


def run() -> Dict:
    by_category = {
        cat: [c for c in CASES if c.category == cat] for cat in ("inspection", "mutation", "opaque")
    }
    result = {"counts": {cat: len(cs) for cat, cs in by_category.items()}, "total": len(CASES)}
    for name, adapter_cls in [("legacy", LegacyShellAdapter), ("current", ShellAdapter)]:
        result[name] = {
            "overall": _rate(CASES, adapter_cls),
            **{cat: _rate(cs, adapter_cls) for cat, cs in by_category.items()},
        }
    return result


def main() -> None:
    m = run()
    print(
        f"realistic shell corpus: {m['total']} commands "
        f"({m['counts']['inspection']} inspection, {m['counts']['mutation']} mutation, "
        f"{m['counts']['opaque']} opaque)\n"
    )
    print(f"fully-classified rate (higher = fewer needless approval prompts)\n")
    print(f"{'adapter':<10}{'overall':>10}{'inspection':>13}{'mutation':>11}{'opaque':>9}")
    print("-" * 53)
    for name in ("legacy", "current"):
        r = m[name]
        print(
            f"{name:<10}{r['overall']*100:>9.0f}%{r['inspection']*100:>12.0f}%"
            f"{r['mutation']*100:>10.0f}%{r['opaque']*100:>8.0f}%"
        )
    print()
    print("'opaque' stays low by design: arbitrary program effect (pip install,")
    print("python script.py, ...) cannot be certified from arguments alone — failing")
    print("closed there is correct, not a false positive.")


if __name__ == "__main__":
    main()
