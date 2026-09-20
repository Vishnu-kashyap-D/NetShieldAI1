"""5.1 -- the pure scoring functions in cyber_ai.hybrid_risk / cyber_ai.data (no server, no models)."""
from __future__ import annotations

import numpy as np
import pytest

from cyber_ai.data import (
    build_window_starts,
    build_window_starts_grouped,
    normalize_label,
    to_attack_category,
    unmapped_attack_labels,
)
from cyber_ai.hybrid_risk import (
    calibrate_anomaly_score_range,
    calibrate_risk_levels,
    compute_risk_score,
    normalize_anomaly_score,
    risk_level_for,
    risk_levels_for,
)


class TestNormalizeAnomalyScore:
    def test_maps_the_calibrated_range_onto_zero_to_one(self):
        assert normalize_anomaly_score([0.0, 5.0, 10.0], low=0.0, high=10.0).tolist() == [0.0, 0.5, 1.0]

    def test_clips_outside_the_range(self):
        assert normalize_anomaly_score([-3.0, 99.0], low=0.0, high=10.0).tolist() == [0.0, 1.0]

    def test_degenerate_range_scores_everything_zero_rather_than_dividing_by_zero(self):
        assert normalize_anomaly_score([1.0, 2.0], low=5.0, high=5.0).tolist() == [0.0, 0.0]


class TestComputeRiskScore:
    def test_without_a_classifier_the_anomaly_score_is_the_risk(self):
        assert compute_risk_score(np.array([0.2, 0.7]), None).tolist() == [0.2, 0.7]

    def test_a_confident_classification_pulls_risk_up(self):
        assert compute_risk_score(np.array([0.3]), np.array([0.95])).tolist() == [0.95]

    def test_classification_can_never_pull_risk_below_the_anomaly_score(self):
        assert compute_risk_score(np.array([0.9]), np.array([0.4])).tolist() == [0.9]

    def test_windows_the_classifier_never_saw_keep_their_anomaly_score(self):
        risk = compute_risk_score(np.array([0.1, 0.5, 0.2]), np.array([np.nan, 0.8, np.nan]))
        assert risk.tolist() == [0.1, 0.8, 0.2]

    def test_does_not_mutate_its_inputs(self):
        anomaly = np.array([0.1, 0.5])
        compute_risk_score(anomaly, np.array([0.9, 0.9]))
        assert anomaly.tolist() == [0.1, 0.5]


class TestRiskLevels:
    @pytest.mark.parametrize(
        "score, level",
        [(0.0, "Low"), (0.299, "Low"), (0.3, "Medium"), (0.799, "Medium"), (0.8, "High"), (1.0, "High")],
    )
    def test_boundaries_belong_to_the_higher_level(self, score, level):
        assert risk_level_for(score, 0.3, 0.8) == level
        assert risk_levels_for(np.array([score]), 0.3, 0.8).tolist() == [level]

    def test_vectorised_matches_scalar_on_a_mixed_batch(self):
        scores = np.array([0.0, 0.5, 0.95, 0.3, 0.8])
        assert risk_levels_for(scores, 0.3, 0.8).tolist() == [risk_level_for(s, 0.3, 0.8) for s in scores]


class TestCalibration:
    def test_anomaly_range_uses_percentiles_so_one_outlier_cannot_flatten_the_scale(self):
        errors = np.concatenate([np.linspace(0.0, 1.0, 100), [1e6]])
        low, high = calibrate_anomaly_score_range(errors)
        assert high < 10  # not dragged to a million by the single outlier

    def test_anomaly_range_is_never_empty(self):
        low, high = calibrate_anomaly_score_range(np.full(50, 0.4))
        assert high > low

    def test_risk_thresholds_come_from_benign_and_attack_scores(self):
        scores = np.array([0.1, 0.1, 0.1, 0.1, 0.1, 0.9, 0.9, 0.9])
        is_attack = np.array([False] * 5 + [True] * 3)
        low, high = calibrate_risk_levels(scores, is_attack)
        assert low == pytest.approx(0.1)   # 90th percentile of the benign scores
        assert high == pytest.approx(0.9)  # median attack score

    def test_risk_thresholds_stay_ordered_even_if_attacks_score_like_benign_traffic(self):
        low, high = calibrate_risk_levels(np.full(10, 0.5), np.array([False] * 5 + [True] * 5))
        assert high > low


class TestLabelsAndCategories:
    @pytest.mark.parametrize(
        "raw, category",
        [
            ("DDoS", "DoS / DDoS"),
            ("DoS Hulk", "DoS / DDoS"),
            ("PortScan", "Port Scanning"),
            ("SSH-Patator", "Brute Force"),
            ("Bot", "Botnet Activity"),
            ("Infiltration", "Data Exfiltration"),
            ("Heartbleed", "Malware Traffic"),
            ("Port Scanning", "Port Scanning"),  # already a category name
        ],
    )
    def test_raw_cicids_labels_map_to_the_six_categories(self, raw, category):
        assert to_attack_category(raw) == category

    @pytest.mark.parametrize("label", ["BENIGN", "Normal", "Normal / Ignored", "something-else-entirely"])
    def test_benign_and_unrecognised_labels_map_to_no_category(self, label):
        assert to_attack_category(label) is None

    def test_label_normalisation_repairs_the_dataset_encoding_quirks(self):
        assert normalize_label("Web Attack � Brute Force") == "Web Attack-Brute Force"
        assert normalize_label("  DoS   Hulk ") == "DoS Hulk"

    def test_unmapped_labels_are_counted_not_silently_dropped(self):
        labels = np.array(["BENIGN", "DDoS", "mystery", "mystery", "other"])
        assert unmapped_attack_labels(labels) == {"mystery": 2, "other": 1}


class TestWindowing:
    def test_stride_one_gives_a_window_ending_on_every_row(self):
        assert build_window_starts(row_count=12, window_size=10, stride=1).tolist() == [0, 1, 2]

    def test_fewer_rows_than_a_window_gives_no_windows(self):
        assert len(build_window_starts(9, 10, 1)) == 0

    def test_grouped_windows_stay_inside_each_source_file(self):
        files = np.array(["a"] * 12 + ["b"] * 11)
        starts = build_window_starts_grouped(files, window_size=10, stride=1)
        # a: rows 0-11 -> starts 0,1,2 ; b: rows 12-22 -> starts 12,13 ; none may span the a|b boundary at 12
        assert starts.tolist() == [0, 1, 2, 12, 13]
