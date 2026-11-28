"""0.89: Cohen, Fleiss and Krippendorff agreement, intervals and degenerate cases."""

from __future__ import annotations

from fractions import Fraction

from opentine._label_stats import bootstrap, cohen, fleiss, krippendorff, passes

PAIRS = [("a", "a"), ("a", "b"), ("b", "b"), ("b", "b")]


def test_cohen_matches_the_hand_computation():
    assert cohen(PAIRS) == (Fraction(1, 2), None)  # po 3/4, pe 1/2


def test_fleiss_and_krippendorff_match_the_hand_computation():
    units = [list(p) for p in PAIRS]
    assert fleiss(units) == (Fraction(7, 15), None)
    assert krippendorff(units) == (Fraction(8, 15), None)


def test_krippendorff_takes_missing_labels_and_skips_single_label_units():
    units = [["a", "a", "a"], ["b", "b"], ["a"], ["a", "b", "b"]]
    value, reason = krippendorff(units)
    assert reason is None and value is not None
    assert krippendorff(units) == krippendorff([u for u in units if len(u) > 1])


def test_degenerate_data_is_undefined_never_a_number():
    assert cohen([])[0] is None
    assert cohen([("a", "a")] * 5)[0] is None  # one category only: chance agreement is 1
    assert fleiss([["a", "a"], ["a", "b", "b"]])[0] is None  # unequal label counts
    assert krippendorff([["a", "a"], ["a", "a"]])[0] is None
    assert krippendorff([["a"], ["b"]])[0] is None


def test_an_undefined_statistic_never_passes_a_floor():
    row = bootstrap([("a", "a")] * 5, cohen, metric="cohen", seed=0, resamples=50,
                    alpha=Fraction(1, 20))  # fmt: skip
    assert row["value"] is None and row["lower"] is None and row["reason"]
    assert not passes(row, Fraction(0))


def test_the_interval_is_seeded_and_brackets_the_value():
    pairs = PAIRS * 8 + [("a", "a")] * 8
    one = bootstrap(pairs, cohen, metric="cohen", seed=3, resamples=200, alpha=Fraction(1, 20))
    two = bootstrap(pairs, cohen, metric="cohen", seed=3, resamples=200, alpha=Fraction(1, 20))
    other = bootstrap(pairs, cohen, metric="cohen", seed=4, resamples=200, alpha=Fraction(1, 20))
    assert one == two and one != other
    assert one["lower"] <= one["value"] <= one["upper"]
    assert passes(one, one["lower"]) and not passes(one, one["lower"] + Fraction(1, 10**9))


def test_too_many_undefined_resamples_make_the_interval_undefined():
    pairs = [("a", "a")] * 9 + [("b", "b")]  # most resamples hold only "a"
    row = bootstrap(pairs, cohen, metric="cohen", seed=0, resamples=100, alpha=Fraction(1, 20))
    assert row["value"] == 1 and row["lower"] is None and row["undefined_resamples"] > 2
    assert not passes(row, Fraction(0))


def test_perfect_agreement_is_one():
    pairs = [("a", "a"), ("b", "b")] * 10
    assert cohen(pairs)[0] == 1 and krippendorff([list(p) for p in pairs])[0] == 1
