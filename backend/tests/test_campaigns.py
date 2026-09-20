"""6.6 -- cross-window campaigns through the engine, ingest and the API."""
from __future__ import annotations

import io

import pandas as pd
import pytest
from sqlalchemy import func, select

from conftest import login
from app.detection_service import load_csv_as_traffic_frame
from app.models import Alert, CorrelatedCampaign
from stub_engine import FEATURES, make_engine

HUNTER, VIEWER = "hunter@example.com", "viewer@example.com"
PARAMS = {"min_confidence": 0.99, "min_windows": 8, "max_gap": 1}


def csv_of(*blocks: tuple[float, int]) -> bytes:
    """A CSV of 10-row windows: each block is (feature value, number of windows)."""
    rows = [{name: value for name in FEATURES} for value, windows in blocks for _ in range(windows * 10)]
    return pd.DataFrame(rows).to_csv(index=False).encode("utf-8")


def quiet_engine(**kwargs):
    """A stand-in model in which a window of value 1.5 is the classic slow attack: the anomaly gate never fires
    (threshold 100 vs an error of 2.25) and the fused risk is 0.14, far under the alert floor (0.5) -- yet the
    classifier reads it as Port Scanning at 99.95% confidence, window after window."""
    engine = make_engine(campaign_params=PARAMS, **kwargs)
    engine.anomaly_threshold = 100.0
    engine.risk_low_threshold, engine.risk_high_threshold = 0.5, 0.9
    return engine


# 5 ordinary windows (value 0: the classifier is only 90% sure of anything), 25 slow-attack windows, 5 ordinary
SLOW_ATTACK = csv_of((0.0, 5), (1.5, 25), (0.0, 5))


def score(csv: bytes, engine, source="cap.csv"):
    return engine.score_dataframe(load_csv_as_traffic_frame(io.BytesIO(csv), source_name=source), include_all_windows=True)


class TestEngine:
    def test_a_slow_attack_the_gate_never_flags_is_still_reported_as_a_campaign(self):
        records, summary = score(SLOW_ATTACK, quiet_engine())
        assert all(r["risk_level"] == "Low" and not r["is_anomaly"] for r in records)   # not one window alerts...
        (campaign,) = summary["campaigns"]                                              # ...yet the layer sees it
        assert campaign["category"] == "Port Scanning" and campaign["windows"] == 25
        assert campaign["alerted_windows"] == 0 and campaign["source_file"] == "cap.csv"
        assert campaign["mean_confidence"] == pytest.approx(0.9995)
        assert campaign["first_window"] == 50 and campaign["last_window"] == (5 + 25 - 1) * 10 + 9

    def test_ordinary_traffic_produces_none(self):
        assert score(csv_of((0.0, 60)), quiet_engine())[1]["campaigns"] == []

    def test_it_is_off_when_not_configured(self):
        _, summary = score(SLOW_ATTACK, make_engine(campaign_params=None))
        assert summary["campaigns"] == []

    def test_it_changes_nothing_about_the_per_window_results(self):
        on, off = quiet_engine(), quiet_engine()
        off.campaign_params = None
        assert score(SLOW_ATTACK, on)[0] == score(SLOW_ATTACK, off)[0]

    def test_it_does_not_disturb_the_summary_either(self):
        on, off = quiet_engine(), quiet_engine()
        off.campaign_params = None
        summary_on, summary_off = score(SLOW_ATTACK, on)[1], score(SLOW_ATTACK, off)[1]
        assert {k: v for k, v in summary_on.items() if k != "campaigns"} == {k: v for k, v in summary_off.items() if k != "campaigns"}

    def test_it_asks_the_classifier_about_windows_the_gate_did_not_flag(self):
        """The whole point: without this the slow attack is invisible, because the classifier only ever sees flagged windows."""
        seen = []
        engine = quiet_engine()
        real_predict = engine.classifier.predict
        engine.classifier.predict = lambda windows, verbose=0: (seen.append(len(windows)), real_predict(windows, verbose=verbose))[1]
        score(SLOW_ATTACK, engine)
        assert sum(seen) == 35                                    # every window, though none was flagged

    def test_without_the_layer_the_classifier_is_not_bothered_with_unflagged_windows(self):
        seen = []
        engine = quiet_engine()
        engine.campaign_params = None
        real_predict = engine.classifier.predict
        engine.classifier.predict = lambda windows, verbose=0: (seen.append(len(windows)), real_predict(windows, verbose=verbose))[1]
        score(SLOW_ATTACK, engine)
        assert sum(seen) == 0

    def test_each_capture_file_is_its_own_stream(self):
        """Two files, each with a run too short to matter alone, must not join across the boundary."""
        engine = quiet_engine()
        first = load_csv_as_traffic_frame(io.BytesIO(csv_of((0.0, 3), (1.5, 5))), source_name="a.csv")
        second = load_csv_as_traffic_frame(io.BytesIO(csv_of((1.5, 5), (0.0, 3))), source_name="b.csv")
        _, summary = engine.score_dataframe(pd.concat([first, second], ignore_index=True), include_all_windows=True)
        assert summary["campaigns"] == []                         # 5 + 5 windows: each below the 8-window minimum

    def test_two_files_can_each_hold_their_own_campaign(self):
        engine = quiet_engine()
        frames = [load_csv_as_traffic_frame(io.BytesIO(SLOW_ATTACK), source_name=name) for name in ("a.csv", "b.csv")]
        _, summary = engine.score_dataframe(pd.concat(frames, ignore_index=True), include_all_windows=True)
        assert sorted(c["source_file"] for c in summary["campaigns"]) == ["a.csv", "b.csv"]

    def test_a_flooding_attack_is_summarised_too_with_its_alerts_counted(self):
        """Windows that DO alert (value 2: flagged, 60% sure) never reach 99% confidence, so they are not a campaign
        -- persistence at high confidence is what the layer looks for, not alert density."""
        _, summary = score(csv_of((2.0, 30)), make_engine(campaign_params=PARAMS))
        assert summary["campaigns"] == []


class TestIngestAndApi:
    @pytest.fixture()
    def slow(self, api, monkeypatch):
        from app.routers import ingest as ingest_router

        monkeypatch.setattr(ingest_router, "get_engine", quiet_engine)
        api.upload = lambda csv=SLOW_ATTACK, name="cap.csv": api.post("/api/ingest/csv", files={"file": (name, csv, "text/csv")})
        login(api, HUNTER)
        return api

    def test_the_upload_reports_the_campaign_though_it_raised_no_alerts(self, slow, session_factory):
        body = slow.upload().json()
        assert body["campaigns_found"] == 1 and body["alerts_written"] == 0 and body["risk_level_counts"] == {}
        with session_factory() as db:
            assert db.execute(select(func.count()).select_from(Alert)).scalar_one() == 0

    def test_the_campaign_is_listed_with_its_evidence(self, slow):
        batch = slow.upload().json()["batch_id"]
        slow.cookies.clear()
        login(slow, VIEWER)
        page = slow.get("/api/campaigns").json()
        assert page["total"] == 1
        item = page["items"][0]
        assert item["batch_id"] == batch and item["source_file"] == "cap.csv" and item["category"] == "Port Scanning"
        assert item["windows"] == 25 and item["alerted_windows"] == 0
        assert item["mean_confidence"] == pytest.approx(0.9995) and (item["first_window"], item["last_window"]) == (50, 299)

    def test_uploading_the_same_file_again_does_not_duplicate_the_campaign(self, slow):
        slow.upload()
        again = slow.upload().json()
        assert again["campaigns_found"] == 1                                  # it still found it...
        assert slow.get("/api/campaigns").json()["total"] == 1                # ...but stored it once

    def test_a_different_file_is_a_different_campaign(self, slow):
        slow.upload(name="one.csv")
        slow.upload(name="two.csv")
        assert slow.get("/api/campaigns").json()["total"] == 2

    def test_filters_and_paging(self, slow):
        slow.upload(name="one.csv")
        slow.upload(name="two.csv")
        assert slow.get("/api/campaigns", params={"source_file": "two.csv"}).json()["total"] == 1
        assert len(slow.get("/api/campaigns", params={"limit": 1}).json()["items"]) == 1
        assert slow.get("/api/campaigns", params={"batch_id": "nope"}).json()["total"] == 0

    @pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 501}, {"offset": -1}])
    def test_out_of_range_paging_is_rejected(self, slow, params):
        assert slow.get("/api/campaigns", params=params).status_code == 422

    def test_signed_out_callers_get_a_401(self, api):
        assert api.get("/api/campaigns").status_code == 401

    def test_a_failure_recording_campaigns_never_fails_the_ingest(self, slow, monkeypatch):
        from app.routers import ingest as ingest_router

        monkeypatch.setattr(ingest_router, "CorrelatedCampaign", None)         # any use of it now raises
        response = slow.upload()
        assert response.status_code == 200 and response.json()["campaigns_found"] == 1

    def test_the_stored_row_is_unique_per_file_and_span(self, slow, session_factory):
        slow.upload()
        with session_factory() as db:
            row = db.execute(select(CorrelatedCampaign)).scalar_one()
            db.add(CorrelatedCampaign(
                batch_id=row.batch_id, source_file=row.source_file, first_window=row.first_window, last_window=1, windows=1,
                alerted_windows=0, category="Port Scanning", mean_confidence=0.999,
            ))
            with pytest.raises(Exception):
                db.commit()


class TestSettings:
    def test_defaults_come_from_the_detector(self, monkeypatch):
        from app.config import Settings
        from cyber_ai import correlation

        for name in ("CAMPAIGN_MIN_CONFIDENCE", "CAMPAIGN_MIN_WINDOWS", "CAMPAIGN_MAX_GAP", "CAMPAIGN_DETECTION_ENABLED"):
            monkeypatch.delenv(name, raising=False)
        s = Settings(_env_file=None)
        assert (s.campaign_min_confidence, s.campaign_min_windows, s.campaign_max_gap) == (
            correlation.DEFAULT_MIN_CONFIDENCE, correlation.DEFAULT_MIN_WINDOWS, correlation.DEFAULT_MAX_GAP
        )
        assert s.campaign_detection_enabled is True

    @pytest.mark.parametrize(
        "name, bad", [("CAMPAIGN_MIN_CONFIDENCE", "0.2"), ("CAMPAIGN_MIN_CONFIDENCE", "1.5"), ("CAMPAIGN_MIN_WINDOWS", "2"), ("CAMPAIGN_MAX_GAP", "-1")]
    )
    def test_nonsense_values_fail_at_startup(self, monkeypatch, name, bad):
        from app.config import Settings

        monkeypatch.setenv(name, bad)
        with pytest.raises(Exception):
            Settings(_env_file=None)

    def test_the_switch_turns_the_layer_off(self, monkeypatch):
        from app import detection_service
        from app.config import settings

        monkeypatch.setattr(settings, "campaign_detection_enabled", False)
        assert detection_service._campaign_params() is None
        monkeypatch.setattr(settings, "campaign_detection_enabled", True)
        assert set(detection_service._campaign_params()) == {"min_confidence", "min_windows", "max_gap"}
