"""Tests for the cumulative session firewall — deciding over the accumulated
effect of a tool-call sequence, which single-call checks structurally miss."""

import pytest

from simdiff.session import Session, SessionBudget, SessionResult
from simdiff.guard import Guard, Decision
from simdiff.delta import CanonicalDelta, DataAccess, ValueMove, AuthorityGrant


class _Fake:
    """An adapter that returns a pre-built delta, so tests control the effect."""
    domain = "fake"

    def simulate(self, action):
        return action

    def extract_delta(self, effect, principal=None):
        return effect  # the action IS the delta in these tests


def _reads(*names):
    return CanonicalDelta(data_access=[DataAccess(resource=n, mode="READ") for n in names])


def _egress(host, amount=10):
    return CanonicalDelta(value_moves=[ValueMove(asset="bytes", src="local", dst=host, amount=amount)])


def _delete(*names):
    return CanonicalDelta(data_access=[DataAccess(resource=n, mode="DELETE") for n in names])


@pytest.fixture
def session():
    guard = Guard({"fake": lambda a: (a["delta"], _Fake())})
    return Session(guard)


def _step(session, delta):
    return session.step("fake", {"delta": delta})


def test_benign_step_allows_and_accumulates(session):
    res = _step(session, _reads("a.txt"))
    assert isinstance(res, SessionResult)
    assert res.decision is Decision.ALLOW
    assert any(d.resource == "a.txt" for d in session.cumulative.data_access)


def test_recon_then_exfil_is_blocked_even_though_each_step_is_benign(session):
    # read a handful of distinct resources (each ALLOW on its own) ...
    for i in range(6):
        assert _step(session, _reads(f"file{i}")).decision is Decision.ALLOW
    # ... then a single egress. Per-call that's only NEEDS_APPROVAL, but in the
    # context of the accumulated reconnaissance the session BLOCKS it.
    res = _step(session, _egress("evil.com"))
    assert res.decision is Decision.BLOCK
    assert any("recon" in r.lower() or "exfil" in r.lower() for r in res.reasons)


def test_enumeration_breadth_needs_approval(session):
    budget = session.budget
    for i in range(budget.max_resources_read):
        _step(session, _reads(f"f{i}"))
    res = _step(session, _reads("one_more"))  # crosses the read-breadth ceiling
    assert res.decision is Decision.NEEDS_APPROVAL
    assert any("enumerat" in r.lower() or "breadth" in r.lower() for r in res.reasons)


def test_mass_deletion_across_steps_needs_approval():
    # individual deletes are permitted (e.g. a scratch area); the *mass* pattern
    # across steps is what the session catches.
    guard = Guard({"fake": lambda a: (a["delta"], _Fake())}, policy=lambda d: Decision.ALLOW)
    session = Session(guard, budget=SessionBudget(max_resources_mutated=3))
    for i in range(3):
        assert session.step("fake", {"delta": _delete(f"d{i}")}).decision is Decision.ALLOW
    res = session.step("fake", {"delta": _delete("final")})
    assert res.decision is Decision.NEEDS_APPROVAL
    assert any("mutat" in r.lower() or "delet" in r.lower() for r in res.reasons)


def test_per_call_block_propagates_and_does_not_accumulate(session):
    res = _step(session, CanonicalDelta(unknown=["unmodelled"]))
    assert res.decision is Decision.BLOCK
    # a blocked action never ran, so its (empty) effect must not pollute the session
    assert session.cumulative.unknown == []
    assert session.step_count == 0


def test_blocked_step_does_not_advance_recon_counter(session):
    # reads that get blocked must not count toward recon breadth
    for i in range(6):
        _step(session, CanonicalDelta(
            data_access=[DataAccess(resource=f"x{i}", mode="READ")],
            unknown=["forced block"],
        ))
    res = _step(session, _egress("evil.com"))
    assert res.decision is not Decision.BLOCK  # no accumulated reads -> not recon→exfil


def test_distinct_egress_host_spread_escalates():
    # allow single egresses (custom permissive per-call policy) to test host spread
    guard = Guard({"fake": lambda a: (a["delta"], _Fake())}, policy=lambda d: Decision.ALLOW)
    session = Session(guard, budget=SessionBudget(max_distinct_egress_hosts=2))
    for host in ("a.com", "b.com"):
        assert session.step("fake", {"delta": _egress(host)}).decision is Decision.ALLOW
    res = session.step("fake", {"delta": _egress("c.com")})  # 3rd distinct host
    assert res.decision is Decision.NEEDS_APPROVAL
    assert any("host" in r.lower() for r in res.reasons)


def test_reset_clears_state(session):
    for i in range(6):
        _step(session, _reads(f"f{i}"))
    session.reset()
    assert session.step_count == 0
    assert session.cumulative.data_access == []
    # after reset, an egress is no longer recon→exfil
    assert _step(session, _egress("evil.com")).decision is not Decision.BLOCK


def test_custom_budget_respected():
    guard = Guard({"fake": lambda a: (a["delta"], _Fake())})
    session = Session(guard, budget=SessionBudget(recon_read_threshold=2))
    _step(session, _reads("a"))
    _step(session, _reads("b"))
    res = _step(session, _egress("evil.com"))
    assert res.decision is Decision.BLOCK  # threshold lowered to 2


def test_sessions_are_independent():
    guard = Guard({"fake": lambda a: (a["delta"], _Fake())})
    s1, s2 = Session(guard), Session(guard)
    for i in range(6):
        _step(s1, _reads(f"f{i}"))
    # s2 is untouched by s1's reconnaissance
    assert _step(s2, _egress("evil.com")).decision is not Decision.BLOCK
