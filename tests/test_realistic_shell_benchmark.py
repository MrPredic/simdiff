"""The realistic-command-stream benchmark, locked into CI.

The README used to carry a bare caveat — "on real command streams the shell
adapter fail-closes on most input, so real-world FP is high, not zero" — with
no number behind it. This pins the actual before/after so it can't drift from
what the code does, and so a future regression that narrows the read-only
vocabulary again gets caught immediately.
"""

from bench.realistic_shell_run import run


def test_current_adapter_substantially_beats_legacy_on_realistic_stream():
    m = run()
    assert m["current"]["overall"] > m["legacy"]["overall"]
    assert m["current"]["overall"] >= 0.75  # was 0.24 before the read-only/pipeline expansion


def test_inspection_commands_are_fully_classified():
    # the whole point: pure reads must not force an approval prompt
    m = run()
    assert m["current"]["inspection"] == 1.0
    assert m["legacy"]["inspection"] < 0.5  # honest baseline: most used to fail closed


def test_mutation_commands_are_unaffected_control():
    # the expansion must not change behavior for commands already modelled
    m = run()
    assert m["current"]["mutation"] == 1.0
    assert m["legacy"]["mutation"] == 1.0


def test_opaque_commands_still_fail_closed_by_design():
    # arbitrary program effect must never be silently certified as safe
    m = run()
    assert m["current"]["opaque"] == 0.0
    assert m["legacy"]["opaque"] == 0.0


def test_corpus_has_all_three_categories():
    m = run()
    assert m["counts"]["inspection"] >= 15
    assert m["counts"]["mutation"] >= 5
    assert m["counts"]["opaque"] >= 5
