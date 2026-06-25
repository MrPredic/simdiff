"""Demo CLI for simdiff.

    simdiff shell "<command line>" [--existing a,b,c] [--json]
    simdiff sql   "<statement>" --db path.sqlite [--json]

Exit code is fail-closed: 0 when the delta is safe (everything classified),
2 when it is not. This makes simdiff usable as a gate in a shell pipeline,
though the real decision belongs to a policy engine consuming the JSON.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from typing import List, Optional

from . import simdiff
from .delta import CanonicalDelta
from .adapters.shell import ShellAdapter
from .adapters.sql import SqlAdapter


def _render_human(delta: CanonicalDelta) -> str:
    lines = [f"safe: {delta.safe}"]
    for d in delta.data_access:
        lines.append(f"  data  {d.mode:6} {d.resource}  ({d.reason})")
    for g in delta.authority_grants:
        lines.append(f"  auth  {g.kind:6} {g.target} {g.old}->{g.new}  ({g.reason})")
    for v in delta.value_moves:
        lines.append(f"  value {v.amount} {v.asset} {v.src}->{v.dst}  ({v.reason})")
    for u in delta.unknown:
        lines.append(f"  UNKNOWN {u}")
    return "\n".join(lines)


def _build(args: argparse.Namespace) -> CanonicalDelta:
    if args.domain == "shell":
        existing = set(args.existing.split(",")) if args.existing else set()
        return simdiff(args.action, ShellAdapter(existing=existing))
    if args.domain == "sql":
        conn = sqlite3.connect(args.db) if args.db else sqlite3.connect(":memory:")
        try:
            return simdiff(args.action, SqlAdapter(conn))
        finally:
            conn.close()
    raise ValueError(f"unknown domain: {args.domain}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="simdiff", description="Simulate an action, print its canonical effect delta.")
    parser.add_argument("domain", choices=["shell", "sql"])
    parser.add_argument("action", help="command line (shell) or statement (sql)")
    parser.add_argument("--existing", help="comma-separated paths that already exist (shell)")
    parser.add_argument("--db", help="path to sqlite database (sql)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of human text")
    args = parser.parse_args(argv)

    delta = _build(args)
    output = json.dumps(delta.to_dict(), indent=2) if args.json else _render_human(delta)
    print(output)
    return 0 if delta.safe else 2


if __name__ == "__main__":
    sys.exit(main())
