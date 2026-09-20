"""6.3 / 6.1 -- the pure maths behind the calibration and abstention analyses (no model, no dataset)."""
from __future__ import annotations

import numpy as np
import pytest

from cyber_ai import abstention_analysis as abstain
from cyber_ai import calibration_check as cal


def test_a_perfectly_calibrated_model_has_zero_ece():
    confidence = np.array([1.0] * 10 + [0.5] * 10)
    correct = np.array([True] * 10 + [True, False] * 5)
    assert cal.expected_calibration_error(confidence, correct) == pytest.approx(0.0)


def test_an_overconfident_model_has_ece_equal_to_the_gap():
    confidence = np.full(100, 0.9)
    correct = np.array([True] * 60 + [False] * 40)   # says 90%, right 60%
    assert cal.expected_calibration_error(confidence, correct) == pytest.approx(0.30)


def test_ece_weights_bins_by_how_many_windows_they_hold():
    confidence = np.array([0.95] * 90 + [0.55] * 10)
    correct = np.array([True] * 90 + [True] * 10)     # 95%-bin is 5 pts under-confident, 55%-bin 45 pts
    assert cal.expected_calibration_error(confidence, correct) == pytest.approx(0.9 * 0.05 + 0.1 * 0.45)


def test_reliability_bins_partition_every_prediction_once():
    rng = np.random.default_rng(0)
    confidence = rng.uniform(0, 1, 500)
    confidence[0] = 1.0                                # the closed right edge must not be dropped
    rows = cal.reliability_bins(confidence, rng.uniform(size=500) < confidence, np.linspace(0, 1, 11))
    assert sum(r["count"] for r in rows) == 500


def test_empty_bins_are_reported_as_empty_not_as_zero_accuracy():
    rows = cal.reliability_bins(np.array([0.95]), np.array([True]), np.array([0.0, 0.5, 1.0000001]))
    assert rows[0]["count"] == 0 and rows[0]["accuracy"] is None


def test_brier_score_is_zero_for_a_certain_correct_model_and_two_for_a_certain_wrong_one():
    probs = np.array([[1.0, 0.0], [0.0, 1.0]])
    assert cal.brier_multiclass(probs, np.array([0, 1])) == pytest.approx(0.0)
    assert cal.brier_multiclass(probs, np.array([1, 0])) == pytest.approx(2.0)


def test_log_loss_punishes_a_confident_mistake_far_more_than_an_unsure_one():
    targets = np.array([0])
    assert cal.log_loss(np.array([[0.01, 0.99]]), targets) > 4 * cal.log_loss(np.array([[0.4, 0.6]]), targets)


def test_wilson_interval_is_wide_for_few_samples_and_tight_for_many():
    small = cal.wilson_interval(1, 1)
    large = cal.wilson_interval(10_000, 10_000)
    assert small[0] < 0.25 and small[1] == pytest.approx(1.0)           # "1 of 1 correct" proves almost nothing
    assert large[0] > 0.999                                             # "10,000 of 10,000" does
    assert cal.wilson_interval(0, 0) == (0.0, 1.0)


def test_temperature_scaling_softens_overconfidence_and_is_neutral_at_one():
    probs = np.array([[0.98, 0.02], [0.02, 0.98]])
    assert cal.apply_temperature(probs, 1.0) == pytest.approx(probs)
    assert cal.apply_temperature(probs, 3.0).max() < probs.max()
    assert cal.apply_temperature(probs, 3.0).sum(axis=1) == pytest.approx([1.0, 1.0])


def test_fitted_temperature_is_above_one_for_an_overconfident_model():
    rng = np.random.default_rng(1)
    n = 2000
    targets = rng.integers(0, 2, n)
    probs = np.where(np.eye(2)[targets] == 1, 0.97, 0.03)      # always 97% sure...
    wrong = rng.uniform(size=n) < 0.25                          # ...but wrong a quarter of the time
    probs[wrong] = probs[wrong][:, ::-1]
    assert cal.fit_temperature(probs, targets) > 1.5


# --- abstention analysis --------------------------------------------------------------------------


def _split(seed=0):
    """Flagged windows: 200 real attacks the classifier is sure of, 100 false alarms it is unsure of."""
    rng = np.random.default_rng(seed)
    n_attack, n_false = 200, 100
    errors = np.ones(n_attack + n_false)                        # all above the anomaly threshold 0.5
    probs = np.zeros((n_attack + n_false, 3))
    confidence = np.concatenate([rng.uniform(0.95, 1.0, n_attack), rng.uniform(0.34, 0.7, n_false)])
    probs[:, 0] = confidence
    probs[:, 1] = (1 - confidence) / 2
    probs[:, 2] = (1 - confidence) / 2
    category = np.concatenate([np.zeros(n_attack, dtype=int), np.full(n_false, -1)])
    is_attack = np.concatenate([np.ones(n_attack, bool), np.zeros(n_false, bool)])
    return errors, probs, is_attack, category


def test_abstention_analysis_reports_what_it_buys_and_what_it_costs():
    result = abstain.analyse_split(*_split(), anomaly_threshold=0.5, thresholds=[0.5, 0.8])
    assert result["auroc_confidence_separates_attacks_from_false_alarms"] > 0.99
    assert (result["known_attack_windows"], result["false_alarm_windows"]) == (200, 100)
    at_08 = result["by_threshold"][1]
    assert at_08["false_alarms_relabelled_unknown"] == 1.0       # every false alarm becomes Unknown...
    assert at_08["known_attacks_relabelled_unknown"] == 0.0      # ...and no real attack does
    assert at_08["accuracy_of_named_attacks"] == 1.0


def test_windows_the_autoencoder_did_not_flag_are_ignored_by_the_analysis():
    errors, probs, is_attack, category = _split()
    errors[:50] = 0.0                                            # 50 attacks the gate missed: never reach the classifier
    result = abstain.analyse_split(errors, probs, is_attack, category, anomaly_threshold=0.5, thresholds=[0.8])
    assert result["known_attack_windows"] == 150


def test_the_recommended_threshold_is_the_strictest_one_that_keeps_detection_categories():
    rows = [
        {"threshold": 0.5, "known_attacks_still_named": 0.99, "accuracy_of_named_attacks": 0.993},
        {"threshold": 0.8, "known_attacks_still_named": 0.98, "accuracy_of_named_attacks": 0.999},
        {"threshold": 0.9, "known_attacks_still_named": 0.975, "accuracy_of_named_attacks": 0.9997},
        {"threshold": 0.99, "known_attacks_still_named": 0.90, "accuracy_of_named_attacks": 1.0},
    ]
    assert abstain.recommend_threshold(rows) == 0.9              # 0.99 names too few real attacks
    assert abstain.recommend_threshold(rows[:1]) is None         # nothing acceptable -> no recommendation
