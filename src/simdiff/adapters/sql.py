"""SQL adapter: simulate a statement inside a savepoint and roll it back.

The action is a single SQL statement (str). It runs against the supplied
``sqlite3`` connection wrapped in a SAVEPOINT that is always rolled back, so the
database is never mutated. The verb determines the access mode; ``cursor.rowcount``
gives the affected-row count. Anything we cannot classify or that errors is
fail-closed.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Optional

from ..delta import CanonicalDelta, DataAccess, ResourceUse

_VERB_RE = re.compile(r"^\s*(\w+)", re.IGNORECASE)
_INSERT_RE = re.compile(r"\binto\s+([`\"\[]?\w+[`\"\]]?)", re.IGNORECASE)
_FROM_RE = re.compile(r"\bfrom\s+([`\"\[]?\w+[`\"\]]?)", re.IGNORECASE)
_UPDATE_RE = re.compile(r"^\s*update\s+([`\"\[]?\w+[`\"\]]?)", re.IGNORECASE)

_MODE_BY_VERB = {"INSERT": "WRITE", "UPDATE": "WRITE", "DELETE": "DELETE", "SELECT": "READ"}


@dataclass
class _SqlEffect:
    verb: Optional[str]
    table: Optional[str]
    rows: int
    error: Optional[str] = None


def _table(sql: str, verb: str) -> Optional[str]:
    if verb == "INSERT":
        m = _INSERT_RE.search(sql)
    elif verb == "UPDATE":
        m = _UPDATE_RE.search(sql)
    else:  # DELETE / SELECT
        m = _FROM_RE.search(sql)
    return m.group(1).strip('`"[]') if m else None


class SqlAdapter:
    domain = "sql"

    def __init__(self, connection: sqlite3.Connection):
        self.conn = connection

    def simulate(self, action: str) -> _SqlEffect:
        verb_match = _VERB_RE.match(action or "")
        verb = verb_match.group(1).upper() if verb_match else None

        if verb not in _MODE_BY_VERB:
            return _SqlEffect(verb=verb, table=None, rows=0, error=f"unsupported statement: {verb}")

        cur = self.conn.cursor()
        cur.execute("SAVEPOINT simdiff")
        error = None
        rows = 0
        try:
            cur.execute(action)
            if verb == "SELECT":
                rows = len(cur.fetchall())
            else:
                rows = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        except Exception as exc:  # noqa: BLE001 - fail-closed
            error = f"{type(exc).__name__}: {exc}"
        finally:
            cur.execute("ROLLBACK TO simdiff")
            cur.execute("RELEASE simdiff")

        return _SqlEffect(verb=verb, table=_table(action, verb), rows=rows, error=error)

    def extract_delta(self, effect: _SqlEffect, principal: Optional[str] = None) -> CanonicalDelta:
        if effect.error is not None:
            return CanonicalDelta(unknown=[f"sql simulation failed: {effect.error}"])

        mode = _MODE_BY_VERB[effect.verb]
        resource = effect.table or "<unknown-table>"
        return CanonicalDelta(
            data_access=[
                DataAccess(
                    resource=resource,
                    mode=mode,
                    bytes=0,
                    reason=f"{effect.verb} affects {effect.rows} row(s)",
                )
            ],
            resource_use=ResourceUse(rows=effect.rows),
        )
