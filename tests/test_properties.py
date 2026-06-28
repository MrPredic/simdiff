"""Property-based / fuzz tests: assert the invariants that make simdiff safe.

Line coverage proves a branch *ran*; these prove the tool upholds its contract
across inputs nobody wrote a test for. A failure here is a real bug, not a flake.
"""

import os
import shutil
import sqlite3
import tempfile

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from simdiff import simdiff
from simdiff.adapters.shell import ShellAdapter
from simdiff.adapters.sql import SqlAdapter
from simdiff.adapters.http import HttpAdapter, HttpRequest
from simdiff.delta import (
    AuthorityGrant,
    CanonicalDelta,
    DataAccess,
    ResourceUse,
    ValueMove,
)


# --- shell: a conservative interpreter must be total and fail-closed ----------

@given(st.text())
@settings(max_examples=400)
def test_shell_is_total_and_returns_a_delta(cmd):
    # INVARIANT: the parser never raises on any input — at worst it fails closed.
    delta = simdiff(cmd, ShellAdapter())
    assert isinstance(delta, CanonicalDelta)


_UNMODELLED_SINGLES = ["|", "$", "`", "*", "?", "~", "<", "{", "}", "[", "]"]


@given(
    metachar=st.sampled_from(_UNMODELLED_SINGLES),
    words=st.lists(st.from_regex(r"[a-z0-9_.]{1,8}", fullmatch=True), max_size=4),
)
@settings(max_examples=300)
def test_shell_standalone_metachar_is_never_certified(metachar, words):
    # INVARIANT: a command carrying an unmodelled metachar as its own token must
    # never be reported as fully classified (it could expand to anything).
    cmd = " ".join(["echo", *words, metachar])
    delta = simdiff(cmd, ShellAdapter())
    assert delta.fully_classified is False


# --- sql: arbitrary statements must never crash the simulator -----------------

@given(st.text())
@settings(max_examples=300, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_sql_is_total_and_returns_a_delta(stmt):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (id INTEGER, v TEXT)")
    conn.commit()
    try:
        delta = simdiff(stmt, SqlAdapter(conn))
        assert isinstance(delta, CanonicalDelta)
    finally:
        conn.close()


# --- http: egress to a non-allow-listed host is always surfaced ---------------

_HOST = st.from_regex(r"[a-z][a-z0-9-]{0,15}(\.[a-z][a-z0-9-]{0,15}){0,3}", fullmatch=True)


@given(host=_HOST, path=st.text(alphabet="abcdef0123/", max_size=20), body=st.text(max_size=40))
@settings(max_examples=300)
def test_http_external_host_is_always_egress(host, path, body):
    # INVARIANT: data leaving to a host that is not allow-listed is always a value
    # move, no matter what the payload looks like (the destination cannot be hidden).
    adapter = HttpAdapter(allowed_hosts=set())
    delta = simdiff(HttpRequest("POST", f"https://{host}/{path}", body=body), adapter)
    assert len(delta.value_moves) == 1
    assert delta.value_moves[0].dst == host.lower()


@given(host=_HOST, body=st.text(max_size=40))
@settings(max_examples=200)
def test_http_allowed_host_is_never_egress(host, body):
    # INVARIANT: the same request to an allow-listed host is never flagged.
    adapter = HttpAdapter(allowed_hosts={host})
    delta = simdiff(HttpRequest("POST", f"https://{host}/x", body=body), adapter)
    assert delta.value_moves == []
    assert delta.fully_classified is True


# --- filesystem: snapshotting must survive any on-disk state ------------------

@st.composite
def _fs_ops(draw):
    name = st.from_regex(r"[a-z0-9_]{1,8}", fullmatch=True)
    op = st.one_of(
        st.tuples(st.just("write"), name, st.binary(max_size=64)),
        st.tuples(st.just("mkdir"), name, st.none()),
        st.tuples(st.just("symlink"), name, name),       # may dangle
        st.tuples(st.just("fifo"), name, st.none()),     # would block a naive hasher
        st.tuples(st.just("remove"), name, st.none()),
        st.tuples(st.just("chmod"), name, st.integers(0, 0o777)),
    )
    return draw(st.lists(op, max_size=5))


def _apply_fs_ops(root, ops):
    for kind, name, arg in ops:
        path = os.path.join(root, name)
        try:
            if kind == "write":
                # O_NONBLOCK so a name-collision with a reader-less FIFO raises
                # (ENXIO) instead of blocking — that would hang the *action*, which
                # is the caller's code, not simdiff. We only fuzz simdiff here.
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NONBLOCK, 0o644)
                try:
                    os.write(fd, arg)
                finally:
                    os.close(fd)
            elif kind == "mkdir":
                os.mkdir(path)
            elif kind == "symlink":
                os.symlink(arg, path)
            elif kind == "fifo":
                os.mkfifo(path)
            elif kind == "remove":
                os.remove(path)
            elif kind == "chmod":
                os.chmod(path, arg)
        except OSError:
            pass  # the action itself failing is fine; simdiff must still not crash


@given(ops=_fs_ops())
@settings(max_examples=120, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_fs_simulate_is_total_under_arbitrary_ops(ops):
    # INVARIANT: no sequence of filesystem ops (incl. symlinks, FIFOs, chmod) makes
    # simulate() raise or hang; it always returns a delta (fail-closed if unsure).
    from simdiff.adapters.filesystem import FilesystemAdapter

    sandbox = tempfile.mkdtemp(prefix="simdiff-prop-")
    try:
        delta = simdiff(lambda root: _apply_fs_ops(root, ops), FilesystemAdapter(sandbox))
        assert isinstance(delta, CanonicalDelta)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


# --- delta algebra: merge is a monoid (associative, with the empty identity) --

_value = st.builds(ValueMove, asset=st.text(max_size=4), src=st.text(max_size=4),
                   dst=st.text(max_size=4), amount=st.floats(allow_nan=False, allow_infinity=False))
_access = st.builds(DataAccess, resource=st.text(max_size=4),
                    mode=st.sampled_from(["READ", "WRITE", "CREATE", "DELETE"]))
_delta = st.builds(
    CanonicalDelta,
    value_moves=st.lists(_value, max_size=3),
    data_access=st.lists(_access, max_size=3),
    unknown=st.lists(st.text(max_size=4), max_size=3),
    resource_use=st.builds(ResourceUse, io_bytes=st.integers(0, 99), rows=st.integers(0, 99)),
)


@given(a=_delta, b=_delta, c=_delta)
@settings(max_examples=200)
def test_merge_is_associative(a, b, c):
    left = a.merge(b).merge(c).to_dict()
    right = a.merge(b.merge(c)).to_dict()
    assert left == right


@given(a=_delta)
@settings(max_examples=100)
def test_merge_with_empty_is_identity(a):
    assert a.merge(CanonicalDelta()).to_dict() == a.to_dict()
