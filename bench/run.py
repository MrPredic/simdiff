"""Run the adversarial corpus through both approaches and report the numbers.

    python -m bench.run

The metrics are also asserted in tests/test_benchmark.py, so the README headline
can never drift from what the code actually does.
"""

from __future__ import annotations

import sqlite3
from typing import Dict

from simdiff import simdiff
from simdiff.adapters.http import HttpAdapter
from simdiff.adapters.shell import ShellAdapter
from simdiff.adapters.sql import SqlAdapter

from .baseline import keyword_flag
from .corpus import CASES, Case, _kw_text
from .policy import effect_flag


def _simdiff_flag(case: Case) -> bool:
    if case.domain == "shell":
        delta = simdiff(case.action, ShellAdapter(existing=case.existing))
    elif case.domain == "http":
        delta = simdiff(
            case.action,
            HttpAdapter(allowed_hosts=case.allowed_hosts, sensitive_markers=case.sensitive_markers),
        )
    elif case.domain == "sql":
        conn = sqlite3.connect(":memory:")
        try:
            for stmt in case.setup:
                conn.execute(stmt)
            conn.commit()
            delta = simdiff(case.action, SqlAdapter(conn))
        finally:
            conn.close()
    else:  # pragma: no cover
        raise ValueError(case.domain)
    return effect_flag(delta, case.protected)


def _score(predictions) -> Dict[str, float]:
    dangerous = [(p, label) for p, label in predictions if label == "dangerous"]
    safe = [(p, label) for p, label in predictions if label == "safe"]
    recall = sum(1 for p, _ in dangerous if p) / len(dangerous)
    fpr = sum(1 for p, _ in safe if p) / len(safe)
    return {"recall": recall, "false_positive_rate": fpr}


def run() -> Dict:
    sd_pred, kw_pred = [], []
    for case in CASES:
        sd_pred.append((_simdiff_flag(case), case.label))
        kw_pred.append((keyword_flag(_kw_text(case.action)), case.label))
    return {
        "simdiff": _score(sd_pred),
        "keyword": _score(kw_pred),
        "counts": {
            "dangerous": sum(1 for c in CASES if c.label == "dangerous"),
            "safe": sum(1 for c in CASES if c.label == "safe"),
            "total": len(CASES),
        },
    }


def main() -> None:
    m = run()
    print(f"corpus: {m['counts']['total']} cases "
          f"({m['counts']['dangerous']} dangerous, {m['counts']['safe']} safe)\n")
    print(f"{'approach':<22}{'recall':>10}{'false positives':>18}")
    print("-" * 50)
    for name, key in [("effect simulation (simdiff)", "simdiff"), ("keyword/arg scanning", "keyword")]:
        s = m[key]
        print(f"{name:<22}{s['recall']*100:>9.0f}%{s['false_positive_rate']*100:>17.0f}%")
    print()
    print("Per-case (technique -> caught by simdiff / by keyword):")
    for case in CASES:
        sd = _simdiff_flag(case)
        kw = keyword_flag(_kw_text(case.action))
        mark = lambda b: "✓" if b else "·"  # noqa: E731
        flag = " " if case.label == "safe" else "!"
        print(f"  {flag} {case.id:<26} sd:{mark(sd)} kw:{mark(kw)}  {case.technique}")


if __name__ == "__main__":
    main()
