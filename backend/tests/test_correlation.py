"""6.6 -- the cross-window persistence detector (cyber_ai/correlation.py), on synthetic streams."""
from __future__ import annotations

import numpy as np
import pytest

from cyber_ai import correlation as corr

WINDOW, STRIDE = 10, 5
FLOOR = 0.3          # risk at which a window is individually an alert
SCAN, BRUTE = 0, 1   # two class ids


def find(classes, confidences, risks=None, first_start=0, **params):
    """Consecutive windows (one stride apart) carrying the given classifier output."""
    n = len(classes)
    starts = first_start + np.arange(n) * STRIDE
    risks = np.zeros(n) if risks is None else np.asarray(risks, dtype=float)
    return corr.find_campaigns(
        starts, np.asarray(classes), np.asarray(confidences, dtype=float), risks, FLOOR, WINDOW, STRIDE, **params
    )


SURE = 0.999


def test_no_windows_no_campaigns():
    assert corr.find_campaigns(np.array([]), np.array([]), np.array([]), np.array([]), FLOOR, WINDOW, STRIDE) == []


def test_a_long_run_of_one_category_at_high_confidence_is_a_campaign():
    (campaign,) = find([SCAN] * 30, [SURE] * 30)
    assert campaign.category == SCAN and campaign.windows == 30
    assert campaign.mean_confidence == pytest.approx(SURE)


def test_it_reports_where_the_activity_is_in_the_source_rows():
    campaign = find([BRUTE] * 5 + [SCAN] * 20 + [BRUTE] * 5, [0.5] * 5 + [SURE] * 20 + [0.5] * 5)[0]
    assert campaign.first_window == 5 * STRIDE
    assert campaign.last_window == (5 + 20 - 1) * STRIDE + WINDOW - 1          # last window's END row
    assert (campaign.first_index, campaign.last_index) == (5, 24)


def test_an_unsure_classifier_is_never_a_campaign():
    """Benign traffic: the classifier (never trained on it) is rarely confident, however consistent its guess."""
    assert find([SCAN] * 100, [0.9] * 100) == []


def test_a_category_that_keeps_changing_is_never_a_campaign():
    """Confident but scattered across categories is what benign traffic looks like, not a sustained activity."""
    classes = [SCAN, BRUTE] * 50
    assert find(classes, [SURE] * 100) == []


def test_a_run_that_is_too_short_is_ignored():
    assert find([SCAN] * 7, [SURE] * 7) == []
    assert len(find([SCAN] * 8, [SURE] * 8)) == 1
    assert len(find([SCAN] * 5, [SURE] * 5, min_windows=5)) == 1


def test_one_off_pattern_window_is_bridged_but_two_in_a_row_end_the_run():
    one_gap = find([SCAN] * 10 + [BRUTE] + [SCAN] * 10, [SURE] * 10 + [0.4] + [SURE] * 10)
    assert len(one_gap) == 1 and one_gap[0].windows == 21
    two_gaps = find([SCAN] * 10 + [BRUTE] * 2 + [SCAN] * 10, [SURE] * 10 + [0.4] * 2 + [SURE] * 10)
    assert len(two_gaps) == 2


def test_a_run_alternating_on_and_off_pattern_is_too_sparse():
    classes = ([SCAN, BRUTE]) * 20
    confidences = ([SURE, 0.4]) * 20                                             # half the windows are off-pattern
    assert find(classes, confidences) == []


def test_two_different_categories_back_to_back_are_two_campaigns():
    campaigns = find([SCAN] * 12 + [BRUTE] * 12, [SURE] * 24)
    assert [c.category for c in campaigns] == [SCAN, BRUTE]
    assert campaigns[0].last_index < campaigns[1].first_index          # in order, sharing no window (rows may overlap)


def test_a_hole_in_the_data_ends_the_run():
    """Two runs each too short alone must not join across a gap in the stream."""
    starts = np.concatenate([np.arange(5) * STRIDE, 10_000 + np.arange(5) * STRIDE])
    classes, confidences = np.full(10, SCAN), np.full(10, SURE)
    split = corr.find_campaigns(starts, classes, confidences, np.zeros(10), FLOOR, WINDOW, STRIDE, min_windows=8)
    joined = corr.find_campaigns(np.arange(10) * STRIDE, classes, confidences, np.zeros(10), FLOOR, WINDOW, STRIDE, min_windows=8)
    assert split == [] and len(joined) == 1


def test_windows_that_alert_on_their_own_are_counted_apart_from_the_quiet_ones():
    risks = [0.05] * 10 + [0.6, 0.6] + [0.05] * 10
    campaign = find([SCAN] * 22, [SURE] * 22, risks)[0]
    assert campaign.alerted_windows == 2 and campaign.quiet_windows == 20


def test_a_campaign_no_window_of_which_alerts_is_exactly_what_this_layer_is_for():
    campaign = find([SCAN] * 25, [SURE] * 25, risks=[0.02] * 25)[0]
    assert campaign.alerted_windows == 0 and campaign.quiet_windows == campaign.windows


def test_input_order_does_not_matter():
    starts = np.arange(30) * STRIDE
    classes, confidences, risks = np.full(30, SCAN), np.full(30, SURE), np.zeros(30)
    shuffle = np.random.default_rng(3).permutation(30)
    ordered = corr.find_campaigns(starts, classes, confidences, risks, FLOOR, WINDOW, STRIDE)
    shuffled = corr.find_campaigns(starts[shuffle], classes[shuffle], confidences[shuffle], risks[shuffle], FLOOR, WINDOW, STRIDE)
    assert ordered == shuffled and len(ordered) == 1


def test_missing_confidence_counts_as_unsure():
    assert find([SCAN] * 40, [np.nan] * 40) == []


def test_a_lower_confidence_bar_admits_more():
    assert find([SCAN] * 20, [0.95] * 20) == []
    assert len(find([SCAN] * 20, [0.95] * 20, min_confidence=0.9)) == 1


def test_the_shipped_defaults_are_sane():
    assert 0.5 < corr.DEFAULT_MIN_CONFIDENCE <= 1.0
    assert corr.DEFAULT_MIN_WINDOWS >= 3 and corr.DEFAULT_MAX_GAP >= 0 and 0 < corr.MIN_DENSITY <= 1
