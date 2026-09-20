"""6.4 -- the feature-space perturbations used by the adversarial-robustness study behave as documented."""
from __future__ import annotations

import numpy as np
import pytest

from cyber_ai import adversarial_robustness as adv

NAMES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Flags",   # "Flags": a feature no perturbation may touch
]
IDX = {n: i for i, n in enumerate(NAMES)}


def one_window(fwd_packets=10.0, bwd_packets=0.0) -> np.ndarray:
    """A single 1-row 'window' with plausible, self-consistent values."""
    row = np.zeros(len(NAMES))
    values = {
        "Flow Duration": 1_000_000.0, "Total Fwd Packets": fwd_packets, "Total Backward Packets": bwd_packets,
        "Total Length of Fwd Packets": fwd_packets * 100, "Total Length of Bwd Packets": bwd_packets * 100,
        "Fwd Packet Length Max": 100.0, "Fwd Packet Length Min": 100.0, "Fwd Packet Length Mean": 100.0,
        "Fwd Packet Length Std": 0.0, "Bwd Packet Length Max": 0.0, "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": 0.0, "Flow Bytes/s": fwd_packets * 100.0, "Flow Packets/s": fwd_packets,
        "Flow IAT Mean": 100_000.0, "Flow IAT Std": 10_000.0, "Flow IAT Max": 150_000.0, "Flow IAT Min": 50_000.0,
        "Min Packet Length": 100.0, "Max Packet Length": 100.0, "Packet Length Mean": 100.0,
        "Average Packet Size": 100.0, "Avg Fwd Segment Size": 100.0, "Avg Bwd Segment Size": 0.0, "Flags": 7.0,
    }
    for name, value in values.items():
        row[IDX[name]] = value
    return row.reshape(1, 1, -1)


def get(windows, name):
    return float(windows[0, 0, IDX[name]])


class TestSlowDown:
    def test_durations_and_gaps_scale_up_and_rates_scale_down(self):
        out = adv.slow_down(one_window(), NAMES, 5.0)
        assert get(out, "Flow Duration") == 5_000_000.0
        assert get(out, "Flow IAT Mean") == 500_000.0
        assert get(out, "Flow IAT Max") == 750_000.0
        assert get(out, "Flow Packets/s") == pytest.approx(2.0)
        assert get(out, "Flow Bytes/s") == pytest.approx(200.0)

    def test_the_traffic_itself_is_unchanged_only_its_pace(self):
        out = adv.slow_down(one_window(), NAMES, 5.0)
        for untouched in ["Total Fwd Packets", "Total Length of Fwd Packets", "Fwd Packet Length Mean", "Flags"]:
            assert get(out, untouched) == get(one_window(), untouched)

    def test_a_factor_of_one_is_the_identity(self):
        assert np.array_equal(adv.slow_down(one_window(), NAMES, 1.0), one_window())

    def test_it_never_modifies_its_input(self):
        original = one_window()
        adv.slow_down(original, NAMES, 9.0)
        assert np.array_equal(original, one_window())


class TestPadding:
    def test_every_packet_grows_by_the_padding_and_the_totals_follow(self):
        out = adv.pad_packets(one_window(fwd_packets=10), NAMES, 50.0)
        assert get(out, "Fwd Packet Length Mean") == 150.0
        assert get(out, "Fwd Packet Length Max") == 150.0
        assert get(out, "Total Length of Fwd Packets") == 10 * 150.0
        assert get(out, "Average Packet Size") == 150.0

    def test_spread_is_unchanged_by_a_constant_shift(self):
        out = adv.pad_packets(one_window(), NAMES, 50.0)
        assert get(out, "Fwd Packet Length Std") == 0.0

    def test_a_direction_with_no_packets_gets_no_padding(self):
        out = adv.pad_packets(one_window(fwd_packets=10, bwd_packets=0), NAMES, 50.0)
        assert get(out, "Bwd Packet Length Mean") == 0.0 and get(out, "Total Length of Bwd Packets") == 0.0
        assert get(out, "Avg Bwd Segment Size") == 0.0

    def test_byte_rate_follows_the_byte_total_but_packet_rate_does_not(self):
        out = adv.pad_packets(one_window(fwd_packets=10), NAMES, 100.0)   # bytes double: 1000 -> 2000
        assert get(out, "Flow Bytes/s") == pytest.approx(2 * 1000.0)
        assert get(out, "Flow Packets/s") == 10.0

    def test_zero_padding_is_the_identity(self):
        assert np.array_equal(adv.pad_packets(one_window(), NAMES, 0.0), one_window())


class TestJitter:
    def test_gap_spread_widens_and_the_extremes_move_apart(self):
        out = adv.add_timing_jitter(one_window(), NAMES, 1.0)   # mean gap 100000, so spread 100000
        assert get(out, "Flow IAT Std") == pytest.approx(np.sqrt(10_000.0 ** 2 + 100_000.0 ** 2))
        assert get(out, "Flow IAT Max") == pytest.approx(150_000.0 + 300_000.0)
        assert get(out, "Flow IAT Min") == 0.0                   # 50000 - 100000 would be negative: clamped

    def test_the_average_gap_is_unchanged(self):
        assert get(adv.add_timing_jitter(one_window(), NAMES, 2.0), "Flow IAT Mean") == 100_000.0

    def test_no_gap_statistic_can_go_negative(self):
        out = adv.add_timing_jitter(one_window(), NAMES, 50.0)
        assert get(out, "Flow IAT Min") >= 0.0

    def test_zero_jitter_is_the_identity(self):
        assert np.array_equal(adv.add_timing_jitter(one_window(), NAMES, 0.0), one_window())


class TestCombine:
    def test_neutral_settings_change_nothing(self):
        assert np.array_equal(adv.combine(one_window(), NAMES), one_window())

    def test_knobs_compose(self):
        out = adv.combine(one_window(), NAMES, slow=2.0, pad=100.0, jitter=1.0)
        assert get(out, "Fwd Packet Length Mean") == 200.0     # padded
        assert get(out, "Flow Duration") == 2_000_000.0        # slowed
        assert get(out, "Flow IAT Std") > 10_000.0 * 2         # jittered, then scaled with the slow-down

    def test_features_a_model_lacks_are_skipped_not_an_error(self):
        few = ["Flow Duration", "Flags"]
        window = np.array([[[1000.0, 3.0]]])
        out = adv.combine(window, few, slow=4.0, pad=50.0, jitter=1.0)
        assert out[0, 0].tolist() == [4000.0, 3.0]

    def test_missing_values_stay_missing(self):
        window = one_window()
        window[0, 0, IDX["Flow IAT Mean"]] = np.nan
        out = adv.combine(window, NAMES, slow=3.0, pad=10.0, jitter=1.0)
        assert np.isnan(get(out, "Flow IAT Mean"))
