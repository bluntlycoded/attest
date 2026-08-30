import math

import pytest

from attest.learn import LogisticModel, RollingFeatures, Standardizer


# ------------------------------------------------------------- standardizer


def test_standardizer_centres_and_scales():
    rows = [{"a": 1.0}, {"a": 3.0}, {"a": 5.0}]
    std = Standardizer().fit(rows)
    assert std.mean == [pytest.approx(3.0)]
    assert std.transform({"a": 3.0}) == [pytest.approx(0.0)]
    assert std.transform({"a": 5.0})[0] > 0


def test_a_constant_feature_becomes_zero_rather_than_dividing_by_zero():
    std = Standardizer().fit([{"a": 7.0}, {"a": 7.0}])
    assert std.transform({"a": 7.0}) == [pytest.approx(0.0)]


def test_missing_features_are_treated_as_zero():
    std = Standardizer().fit([{"a": 1.0, "b": 2.0}, {"a": 3.0, "b": 4.0}])
    assert len(std.transform({"a": 1.0})) == 2


def test_standardizer_needs_rows():
    with pytest.raises(ValueError, match="no rows"):
        Standardizer().fit([])


# ----------------------------------------------------------- rolling features


def test_novelty_fires_on_first_sight_then_stops():
    rolling = RollingFeatures(warmup=0)
    first = rolling.observe(0.0, {"host": "a"}, peer="a")
    second = rolling.observe(1.0, {"host": "a"}, peer="a")
    assert first["new_host"] == 1.0
    assert second["new_host"] == 0.0


def test_novelty_is_damped_during_warmup():
    """Everything is new to a fresh entity; that is not evidence."""
    cold = RollingFeatures(warmup=50).observe(0.0, {"host": "a"})
    warm = RollingFeatures(warmup=0).observe(0.0, {"host": "a"})
    assert cold["new_host"] < warm["new_host"]
    assert cold["cold_start"] == 1.0


def test_breadth_counts_distinct_peers_in_the_window():
    """Reaching many hosts quickly is the lateral movement signature."""
    rolling = RollingFeatures(breadth_window=100.0, warmup=0)
    narrow = [rolling.observe(float(i), {"h": "x"}, peer="host-a") for i in range(5)]
    wide = [
        rolling.observe(10.0 + i, {"h": "x"}, peer=f"host-{i}") for i in range(5)
    ]
    assert wide[-1]["breadth"] > narrow[-1]["breadth"]


def test_breadth_forgets_peers_outside_the_window():
    rolling = RollingFeatures(breadth_window=10.0, warmup=0)
    for i in range(5):
        rolling.observe(float(i), {"h": "x"}, peer=f"host-{i}")
    later = rolling.observe(1000.0, {"h": "x"}, peer="host-new")
    assert later["breadth"] == pytest.approx(math.log1p(1))


def test_burst_rises_when_events_arrive_faster_than_usual():
    rolling = RollingFeatures(warmup=0)
    for i in range(20):
        steady = rolling.observe(i * 100.0, {"h": "x"})
    # 1 second after the last event, against a baseline gap of 100.
    fast = rolling.observe(19 * 100.0 + 1.0, {"h": "x"})
    assert steady["burst"] == pytest.approx(0.0, abs=1e-6)
    assert fast["burst"] > 0.9


# ------------------------------------------------------------------- model


def _separable(n=400):
    rows, labels = [], []
    for i in range(n):
        hostile = i % 4 == 0
        rows.append(
            {"signal": 3.0 if hostile else -1.0, "noise": (i % 7) / 7.0}
        )
        labels.append(1 if hostile else 0)
    return rows, labels


def test_model_learns_a_separable_signal():
    rows, labels = _separable()
    model = LogisticModel(epochs=60).fit(rows, labels)
    assert model.score({"signal": 3.0, "noise": 0.5}) > 0.8
    assert model.score({"signal": -1.0, "noise": 0.5}) < 0.1


def test_more_epochs_sharpen_the_separation():
    """Guards the learning-rate schedule; 1/(1+epoch) barely moves after ten."""
    rows, labels = _separable()
    few = LogisticModel(epochs=10).fit(rows, labels)
    many = LogisticModel(epochs=80).fit(rows, labels)
    margin = lambda m: m.score({"signal": 3.0, "noise": 0.5}) - m.score(
        {"signal": -1.0, "noise": 0.5}
    )
    assert margin(many) > margin(few) + 0.1


def test_class_weighting_does_not_leave_scores_inflated():
    """Training on a reweighted population would otherwise skew every score.

    The recurrence reads p as an expected count of bad evidence, so a
    systematic factor-of-w inflation is not cosmetic - it shifts every trust
    trajectory. The prior correction is what keeps the raw scores usable.
    """
    rows, labels = [], []
    for i in range(2000):
        hostile = i % 100 == 0
        rows.append({"signal": 4.0 if hostile else -1.0})
        labels.append(1 if hostile else 0)

    model = LogisticModel(epochs=20).fit(rows, labels)
    benign = [model.score(r) for r, y in zip(rows, labels) if not y]
    mean_benign = sum(benign) / len(benign)

    # The true base rate is 1%. Without the correction this sits near 0.5.
    assert mean_benign < 0.1


def test_the_informative_feature_gets_the_largest_weight():
    """The whole model is readable, which is the point of keeping it small."""
    rows, labels = _separable()
    model = LogisticModel(epochs=60).fit(rows, labels)
    assert model.coefficients()[0][0] == "signal"


def test_rare_positives_are_not_ignored():
    """Unweighted training on a 1% base rate collapses to 'always clean'."""
    rows, labels = [], []
    for i in range(2000):
        hostile = i % 100 == 0
        rows.append({"signal": 4.0 if hostile else -1.0})
        labels.append(1 if hostile else 0)

    model = LogisticModel(epochs=20).fit(rows, labels)
    assert model.score({"signal": 4.0}) > 0.5


def test_calibration_changes_the_reported_probability():
    rows, labels = _separable()
    model = LogisticModel(epochs=20).fit(rows, labels)
    before = model.score({"signal": 3.0, "noise": 0.5})
    model.calibrate(rows, labels)
    assert model.calibrator.temperature != 1.0
    assert model.score({"signal": 3.0, "noise": 0.5}) != before


def test_scoring_before_fitting_is_an_error():
    with pytest.raises(RuntimeError, match="not been fitted"):
        LogisticModel().score({"a": 1.0})


def test_mismatched_training_input_is_rejected():
    with pytest.raises(ValueError, match="differ in length"):
        LogisticModel().fit([{"a": 1.0}], [1, 0])


def test_empty_training_set_is_rejected():
    with pytest.raises(ValueError, match="empty training set"):
        LogisticModel().fit([], [])


def test_large_logits_do_not_overflow():
    model = LogisticModel(epochs=1).fit(
        [{"a": 1.0}, {"a": -1.0}], [1, 0]
    )
    model.weights = [1e6]
    assert 0.0 <= model.score({"a": 1.0}) <= 1.0
    assert 0.0 <= model.score({"a": -1.0}) <= 1.0
