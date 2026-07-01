"""The multi-step claim, locked into CI.

The cumulative session firewall must catch every multi-step attack whose
individual calls are benign, at zero false positives — and it must strictly beat
a per-call check running the *same* effect engine, because single-call decisions
are structurally blind to the accumulated composition. If this ever regresses,
CI fails, so the README number cannot drift from reality.
"""

from bench.session_run import run


def test_session_catches_every_multistep_attack_zero_fp():
    m = run()
    assert m["session"]["recall"] == 1.0
    assert m["session"]["false_positive_rate"] == 0.0


def test_session_strictly_beats_per_call_baseline():
    m = run()
    assert m["session"]["recall"] > m["per_call"]["recall"]
    # a permissive-enough-to-be-usable per-call policy is blind to composition:
    # it lets every step of these attacks through
    assert m["per_call"]["recall"] == 0.0


def test_neither_approach_has_false_positives_on_benign_work():
    # the point is not just recall; the session must not tax legitimate multi-step
    # work, and the permissive baseline (by construction) does not either
    m = run()
    assert m["session"]["false_positive_rate"] == 0.0
    assert m["per_call"]["false_positive_rate"] == 0.0


def test_corpus_has_both_classes():
    m = run()
    assert m["counts"]["attack"] >= 6
    assert m["counts"]["benign"] >= 5
