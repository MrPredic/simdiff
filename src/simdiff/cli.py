"""Demo CLI for simdiff.

    simdiff shell "<command line>" [--existing a,b,c] [--json]
    simdiff sql   "<statement>" --db path.sqlite [--json]
    simdiff http  "<url>" [--method POST] [--body ...] [--allowed-hosts a,b] [--json]

Exit code is fail-closed: 0 when the effect was fully classified, 2 when
something could not be (``unknown``). This is a classification gate, NOT a safety
verdict -- a fully-classified delta can still be a destructive delete or an
exfil. The real allow/block decision belongs to a policy engine consuming the
JSON.
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
from .adapters.http import HttpAdapter, HttpRequest


def _csv(value: Optional[str]) -> set:
    return {p.strip() for p in value.split(",") if p.strip()} if value else set()


def _render_human(delta: CanonicalDelta) -> str:
    lines = [f"fully_classified: {delta.fully_classified}  (classification only, NOT a safety verdict)"]
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
        return simdiff(args.action, ShellAdapter(existing=_csv(args.existing)))
    if args.domain == "sql":
        conn = sqlite3.connect(args.db) if args.db else sqlite3.connect(":memory:")
        try:
            return simdiff(args.action, SqlAdapter(conn))
        finally:
            conn.close()
    if args.domain == "http":
        req = HttpRequest(method=args.method, url=args.action, body=args.body or "")
        adapter = HttpAdapter(allowed_hosts=_csv(args.allowed_hosts), sensitive_markers=_csv(args.sensitive))
        return simdiff(req, adapter)
    raise ValueError(f"unknown domain: {args.domain}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="simdiff", description="Simulate an action, print its canonical effect delta.")
    parser.add_argument("domain", choices=["shell", "sql", "http"])
    parser.add_argument("action", help="command line (shell), statement (sql), or url (http)")
    parser.add_argument("--existing", help="comma-separated paths that already exist (shell)")
    parser.add_argument("--db", help="path to sqlite database (sql)")
    parser.add_argument("--method", default="GET", help="HTTP method (http)")
    parser.add_argument("--body", help="request body (http)")
    parser.add_argument("--allowed-hosts", dest="allowed_hosts", help="comma-separated egress allowlist (http)")
    parser.add_argument("--sensitive", help="comma-separated sensitive markers to flag in egress (http)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of human text")
    args = parser.parse_args(argv)

    delta = _build(args)
    output = json.dumps(delta.to_dict(), indent=2) if args.json else _render_human(delta)
    print(output)
    return 0 if delta.fully_classified else 2


if __name__ == "__main__":
    sys.exit(main())
