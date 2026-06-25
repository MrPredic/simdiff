"""The benchmark claim, locked into CI.

simdiff must catch every obfuscated-effect attack at zero false positives, and
must strictly beat signature/keyword argument scanning on recall. If this ever
regresses, CI fails — the README number cannot drift from reality.
"""

from bench.run import run


def test_simdiff_perfect_recall_zero_fp():
    m = run()
    assert m["simdiff"]["recall"] == 1.0
    assert m["simdiff"]["false_positive_rate"] == 0.0


def test_simdiff_strictly_beats_keyword_scanning_on_recall():
    m = run()
    assert m["simdiff"]["recall"] > m["keyword"]["recall"]
    # keyword scanning misses the obfuscated majority
    assert m["keyword"]["recall"] < 0.5


def test_corpus_has_both_classes():
    m = run()
    assert m["counts"]["dangerous"] >= 6
    assert m["counts"]["safe"] >= 5
