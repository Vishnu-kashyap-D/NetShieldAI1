"""6.5 -- concept-drift monitoring: reference, per-ingest histograms, PSI assessment, the /api/stats/drift endpoint."""
from __future__ import annotations

import datetime as dt
import json

import numpy as np
import pytest
from sqlalchemy import select

from conftest import login
from app.config import settings
from app.models import ScoreBatch
from cyber_ai import drift
from stub_engine import known_traffic_csv, make_engine

VIEWER, HUNTER = "viewer@example.com", "hunter@example.com"
THRESHOLD = 10.0


def reference_from(quiet_scores: np.ndarray, flag_rate: float = 0.1) -> dict:
    errors = np.concatenate([quiet_scores, np.full(int(len(quiet_scores) * flag_rate / (1 - flag_rate)) + 1, THRESHOLD * 2)])
    return drift.build_reference(errors, np.ones(len(errors), dtype=bool), THRESHOLD)


@pytest.fixture()
def rng():
    return np.random.default_rng(7)


@pytest.fixture()
def reference(rng):
    return reference_from(rng.gamma(2.0, 1.0, 5000))          # ordinary traffic: scores well under the threshold


# --- the reference ---------------------------------------------------------------------------------


class TestBuildReference:
    def test_bins_are_quantiles_so_each_holds_about_a_tenth_of_quiet_traffic(self, reference):
        assert len(reference["bin_edges"]) == 9 and len(reference["expected_proportions"]) == 10
        assert sum(reference["expected_proportions"]) == pytest.approx(1.0)
        assert all(0.09 < p < 0.11 for p in reference["expected_proportions"])
        assert reference["bin_edges"] == sorted(reference["bin_edges"])

    def test_only_benign_unflagged_windows_describe_what_quiet_looks_like(self):
        errors = np.array([1.0] * 300 + [50.0] * 100 + [2.0] * 100)     # 300 quiet benign, 100 flagged, 100 "attacks"
        benign = np.array([True] * 400 + [False] * 100)
        ref = drift.build_reference(errors, benign, anomaly_threshold=10.0)
        assert ref["reference_windows"] == 300
        assert ref["benign_flag_rate"] == pytest.approx(100 / 400)       # false-alarm rate among benign windows

    def test_too_few_windows_to_describe_a_distribution_gives_no_reference(self):
        assert drift.build_reference(np.ones(50), np.ones(50, bool), 10.0) is None

    def test_a_reference_is_identified_by_its_model_so_stale_counts_are_detectable(self, reference):
        same = json.loads(json.dumps(reference))
        assert drift.reference_id(same) == drift.reference_id(reference)
        other = {**reference, "anomaly_threshold": reference["anomaly_threshold"] + 1}
        assert drift.reference_id(other) != drift.reference_id(reference)


class TestLoadReference:
    def test_round_trips_through_the_file(self, tmp_path, reference):
        (tmp_path / drift.REFERENCE_FILENAME).write_text(json.dumps(reference), encoding="utf-8")
        assert drift.load_reference(tmp_path) == reference

    @pytest.mark.parametrize("content", [None, "{not json", "[]", '{"anomaly_threshold": 1}'], ids=["missing", "garbage", "wrong-type", "incomplete"])
    def test_a_missing_or_unusable_file_means_no_reference_never_a_crash(self, tmp_path, content):
        if content is not None:
            (tmp_path / drift.REFERENCE_FILENAME).write_text(content, encoding="utf-8")
        assert drift.load_reference(tmp_path) is None


# --- binning and PSI -------------------------------------------------------------------------------


class TestBinning:
    def test_every_window_lands_in_exactly_one_place(self, reference, rng):
        scores = np.concatenate([rng.gamma(2.0, 1.0, 900), np.full(100, THRESHOLD * 3)])
        counts = drift.bin_scores(scores, reference)
        assert counts["flagged_windows"] == 100
        assert sum(counts["quiet_bin_counts"]) == counts["quiet_windows"] == 900

    def test_a_score_exactly_at_the_threshold_is_still_quiet(self, reference):
        counts = drift.bin_scores(np.array([THRESHOLD]), reference)
        assert counts["quiet_windows"] == 1 and counts["flagged_windows"] == 0


class TestPsi:
    def test_identical_distributions_score_zero(self):
        assert drift.psi(np.full(10, 0.1), np.full(10, 100)) == pytest.approx(0.0, abs=1e-9)

    def test_the_bigger_the_shift_the_bigger_the_psi(self):
        expected = np.full(10, 0.1)
        small = drift.psi(expected, np.array([120, 100, 100, 100, 100, 100, 100, 100, 100, 80]))
        large = drift.psi(expected, np.array([400, 300, 100, 50, 50, 25, 25, 20, 20, 10]))
        assert 0 < small < 0.1 < large

    def test_an_empty_live_bin_does_not_blow_up(self):
        assert np.isfinite(drift.psi(np.full(10, 0.1), np.array([0, 200, 200, 200, 200, 200, 0, 0, 0, 0])))


# --- assessment ------------------------------------------------------------------------------------


def batch_of(scores, reference):
    return drift.bin_scores(np.asarray(scores), reference)


class TestAssess:
    def test_traffic_like_the_reference_is_stable(self, reference, rng):
        result = drift.assess(reference, [batch_of(rng.gamma(2.0, 1.0, 3000), reference)])
        assert result["status"] == "stable" and result["psi"] < drift.PSI_WATCH

    def test_ordinary_traffic_that_now_scores_higher_is_drift(self, reference, rng):
        result = drift.assess(reference, [batch_of(rng.gamma(2.0, 1.0, 3000) * 1.6, reference)])
        assert result["status"] in {"watch", "drifting"} and result["psi"] > drift.PSI_WATCH

    def test_a_large_shift_is_drifting(self, reference, rng):
        result = drift.assess(reference, [batch_of(rng.gamma(2.0, 1.0, 3000) * 0.4, reference)])
        assert result["status"] == "drifting" and result["psi"] > drift.PSI_DRIFTING

    def test_too_little_traffic_is_reported_as_such_not_as_stable(self, reference, rng):
        result = drift.assess(reference, [batch_of(rng.gamma(2.0, 1.0, 50), reference)])
        assert result["status"] == "insufficient_data" and result["psi"] is None

    def test_no_traffic_at_all_is_insufficient(self, reference):
        assert drift.assess(reference, [])["status"] == "insufficient_data"

    def test_a_burst_of_real_attacks_is_not_mistaken_for_drift(self, reference, rng):
        """Attacks push windows over the anomaly threshold; only the quiet end is compared, so PSI stays put."""
        ordinary = rng.gamma(2.0, 1.0, 3000)
        attack_burst = np.full(6000, THRESHOLD * 5)
        calm = drift.assess(reference, [batch_of(ordinary, reference)])
        burst = drift.assess(reference, [batch_of(ordinary, reference), batch_of(attack_burst, reference)])
        assert burst["status"] == "stable" and burst["psi"] == pytest.approx(calm["psi"])
        assert burst["flag_rate"] > 0.6 and burst["flag_rate_ratio"] > 5          # ...but the alert rate is visible

    def test_batches_are_pooled(self, reference, rng):
        pieces = [batch_of(rng.gamma(2.0, 1.0, 100), reference) for _ in range(6)]
        pooled = drift.assess(reference, pieces)
        assert pooled["quiet_windows"] == 600 and pooled["status"] != "insufficient_data"

    def test_the_result_carries_the_bin_comparison_for_a_chart(self, reference, rng):
        result = drift.assess(reference, [batch_of(rng.gamma(2.0, 1.0, 3000), reference)])
        assert len(result["bins"]) == 10
        assert sum(b["live"] for b in result["bins"]) == pytest.approx(1.0)


# --- through the engine and the API ----------------------------------------------------------------

STUB_REFERENCE = {
    "anomaly_threshold": 1.0,                 # the stand-in engine's threshold
    "bin_edges": [0.5],
    "expected_proportions": [0.5, 0.5],
    "reference_windows": 1000,
    "benign_flag_rate": 0.1,
}


def test_the_engine_reports_every_windows_score_bin_not_just_the_stored_ones():
    import io

    from app.detection_service import load_csv_as_traffic_frame

    frame = load_csv_as_traffic_frame(io.BytesIO(known_traffic_csv()), source_name="k.csv")
    _, summary = make_engine(drift_reference=STUB_REFERENCE).score_dataframe(frame)   # default: Low windows are dropped
    distribution = summary["score_distribution"]
    assert distribution["quiet_bin_counts"] == [2, 0]         # the two Low windows are still counted...
    assert distribution["flagged_windows"] == 2               # ...alongside the two alerts
    assert distribution["reference_id"] == drift.reference_id(STUB_REFERENCE)


def test_without_a_reference_the_engine_reports_nothing_and_scoring_is_unchanged():
    import io

    from app.detection_service import load_csv_as_traffic_frame

    frame = load_csv_as_traffic_frame(io.BytesIO(known_traffic_csv()), source_name="k.csv")
    records, summary = make_engine(drift_reference=None).score_dataframe(frame)
    assert summary["score_distribution"] is None and len(records) == 2


@pytest.fixture()
def drift_api(api, session_factory, monkeypatch, tmp_path):
    """An API whose engine has a drift reference, with a matching reference file in a scratch artifacts dir."""
    from app.routers import ingest as ingest_router

    (tmp_path / drift.REFERENCE_FILENAME).write_text(json.dumps(STUB_REFERENCE), encoding="utf-8")
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path)
    monkeypatch.setattr(ingest_router, "get_engine", lambda: make_engine(drift_reference=STUB_REFERENCE))
    api.session_factory = session_factory
    api.artifacts = tmp_path
    return api


def upload(client, name="k.csv", **params):
    return client.post("/api/ingest/csv", params=params, files={"file": (name, known_traffic_csv(), "text/csv")})


class TestIngestRecordsDistributions:
    def rows(self, api):
        with api.session_factory() as db:
            return db.execute(select(ScoreBatch)).scalars().all()

    def test_an_ingest_leaves_one_histogram_row(self, drift_api):
        login(drift_api, HUNTER)
        assert upload(drift_api).status_code == 200
        (row,) = self.rows(drift_api)
        assert row.quiet_bin_counts == [2, 0] and row.flagged_windows == 2 and row.windows_scored == 4
        assert row.reference_id == drift.reference_id(STUB_REFERENCE) and row.source_file == "k.csv"

    def test_re_sending_the_same_file_is_the_same_traffic_not_more_of_it(self, drift_api, caplog):
        login(drift_api, HUNTER)
        upload(drift_api)
        with caplog.at_level("ERROR", logger="netshield.backend"):
            upload(drift_api)
        assert len(self.rows(drift_api)) == 1
        # ...and it is recognised up front, not by tripping the database's unique constraint and logging an error
        assert not [r for r in caplog.records if "score distribution" in r.getMessage()]

    def test_a_deliberate_replay_counts_as_new_traffic(self, drift_api):
        login(drift_api, HUNTER)
        upload(drift_api, allow_duplicates="true")
        upload(drift_api, allow_duplicates="true")
        assert len(self.rows(drift_api)) == 2

    def test_a_failure_recording_drift_data_never_fails_the_ingest(self, drift_api, monkeypatch):
        from app.routers import ingest as ingest_router

        monkeypatch.setattr(ingest_router, "ScoreBatch", lambda **kw: (_ for _ in ()).throw(RuntimeError("db hiccup")))
        login(drift_api, HUNTER)
        response = upload(drift_api)
        assert response.status_code == 200 and response.json()["alerts_written"] == 2


def seed_batch(api, counts, flagged, reference_id_=None, age_hours=0, batch_id=None):
    with api.session_factory() as db:
        db.add(ScoreBatch(
            batch_id=batch_id or f"b{np.random.randint(10**9)}", source_file="t.csv",
            reference_id=reference_id_ or drift.reference_id(STUB_REFERENCE), windows_scored=sum(counts) + flagged,
            flagged_windows=flagged, quiet_bin_counts=counts,
            ingested_at=dt.datetime.utcnow() - dt.timedelta(hours=age_hours),
        ))
        db.commit()


class TestDriftEndpoint:
    def get(self, api, **params):
        return api.get("/api/stats/drift", params=params)

    def test_it_needs_a_session_but_any_role_will_do(self, drift_api):
        assert self.get(drift_api).status_code == 401
        login(drift_api, VIEWER)
        assert self.get(drift_api).status_code == 200

    def test_no_reference_for_the_model_is_reported_honestly(self, drift_api):
        (drift_api.artifacts / drift.REFERENCE_FILENAME).unlink()
        login(drift_api, VIEWER)
        body = self.get(drift_api).json()
        assert body["status"] == "unavailable" and "cyber_ai.drift" in body["message"]

    def test_no_ingests_yet_is_insufficient_data(self, drift_api):
        login(drift_api, VIEWER)
        assert self.get(drift_api).json()["status"] == "insufficient_data"

    def test_traffic_matching_the_reference_is_stable(self, drift_api):
        seed_batch(drift_api, [500, 500], flagged=100)
        login(drift_api, VIEWER)
        body = self.get(drift_api).json()
        assert body["status"] == "stable" and body["psi"] < 0.1
        assert body["windows"] == 1100 and body["quiet_windows"] == 1000
        assert body["flag_rate"] == pytest.approx(100 / 1100) and body["reference_flag_rate"] == 0.1
        assert body["psi_watch"] == 0.1 and body["psi_drifting"] == 0.25

    def test_a_shifted_distribution_is_flagged_as_drifting(self, drift_api):
        seed_batch(drift_api, [950, 50], flagged=0)
        login(drift_api, VIEWER)
        body = self.get(drift_api).json()
        assert body["status"] == "drifting" and body["psi"] > 0.25
        assert [b["live"] for b in body["bins"]] == [0.95, 0.05]

    def test_batches_are_pooled_across_ingests(self, drift_api):
        for _ in range(4):
            seed_batch(drift_api, [60, 60], flagged=5)
        login(drift_api, VIEWER)
        body = self.get(drift_api).json()
        assert body["batches_considered"] == 4 and body["quiet_windows"] == 480 and body["status"] == "stable"

    def test_only_the_requested_period_is_considered(self, drift_api):
        seed_batch(drift_api, [500, 500], flagged=0, age_hours=1)
        seed_batch(drift_api, [950, 50], flagged=0, age_hours=48)        # skewed, but two days old
        login(drift_api, VIEWER)
        assert self.get(drift_api, hours=24).json()["status"] == "stable"
        assert self.get(drift_api, hours=72).json()["batches_considered"] == 2

    def test_counts_binned_for_an_earlier_model_are_excluded_not_compared(self, drift_api):
        seed_batch(drift_api, [500, 500], flagged=0)
        seed_batch(drift_api, [1000, 0], flagged=0, reference_id_="oldmodel")
        login(drift_api, VIEWER)
        body = self.get(drift_api).json()
        assert body["batches_considered"] == 1 and body["batches_excluded"] == 1 and body["status"] == "stable"

    @pytest.mark.parametrize("hours", [0, 721])
    def test_an_out_of_range_period_is_rejected(self, drift_api, hours):
        login(drift_api, VIEWER)
        assert self.get(drift_api, hours=hours).status_code == 422
