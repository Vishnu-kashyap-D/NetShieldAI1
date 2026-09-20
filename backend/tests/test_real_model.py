"""5.1 -- smoke tests against the REAL committed model (artifacts/) and the curated demo CSV.

The other tests use stand-in models so their expected values can be worked out by hand. These check
what those cannot: that the shipped artifacts still load under the installed library versions (a
scikit-learn / Keras mismatch surfaces here first -- see the pin note in requirements.txt), and that
the model still behaves the way the demo narrative claims. They need a TensorFlow model load, so
they take ~30s; deselect them with `-m "not real_model"` for a fast run.

If a retrain is *deliberately* accepted, the narrative assertions below may need updating -- that
is the point: they turn "the model quietly changed" into a visible failure.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from conftest import login

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO_ROOT / "artifacts"
DEMO_CSV = REPO_ROOT / "demo" / "panel_demo_traffic.csv"

pytestmark = [
    pytest.mark.real_model,
    pytest.mark.skipif(
        not (ARTIFACTS / "preprocessing.joblib").exists() or not DEMO_CSV.exists(),
        reason="needs the committed artifacts/ and demo/panel_demo_traffic.csv",
    ),
]

KNOWN_PREDICTIONS = {"Normal", "Brute Force", "Malware Traffic", "Botnet Activity", "Data Exfiltration", "DoS / DDoS", "Port Scanning"}


@pytest.fixture(scope="module")
def engine():
    from app.detection_service import DetectionEngine

    return DetectionEngine(ARTIFACTS)


@pytest.fixture(scope="module")
def scored(engine):
    from app.detection_service import load_csv_as_traffic_frame

    frame = load_csv_as_traffic_frame(DEMO_CSV, DEMO_CSV.name)
    records, summary = engine.score_dataframe(frame, include_all_windows=True)
    return frame, records, summary


def test_the_committed_artifacts_load_and_are_internally_consistent(engine):
    assert len(engine.feature_names) == 76
    assert "Destination Port" not in engine.feature_names       # the known leakage feature stays excluded
    assert engine.window_size == 10 and engine.stride > 0
    assert 0 < engine.risk_low_threshold < engine.risk_high_threshold <= 1.0
    assert engine.anomaly_score_high > engine.anomaly_score_low
    assert len(engine.feature_schema_version) == 12


def test_every_window_of_the_demo_csv_is_scored_and_accounted_for(scored):
    frame, records, summary = scored
    engine_window, stride = 10, 5
    assert summary["windows_scored"] == (len(frame) - engine_window) // stride + 1
    assert len(records) == summary["windows_scored"]           # include_all_windows keeps them all
    assert sum(summary["risk_level_counts"].values()) == summary["windows_scored"]
    assert sum(summary["predicted_label_counts"].values()) == summary["windows_scored"]
    assert sum(r["is_anomaly"] for r in records) == summary["anomalous_windows"]


def test_every_record_is_well_formed(scored, engine):
    _, records, _ = scored
    for record in records:
        assert 0.0 <= record["risk_score"] <= 1.0
        assert record["risk_level"] in {"Low", "Medium", "High"}
        assert record["predicted_label"] in KNOWN_PREDICTIONS
        assert set(record["features"]) == set(engine.feature_names)
        if not record["is_anomaly"]:  # below the anomaly gate: never classified
            assert record["predicted_label"] == "Normal" and record["confidence"] == 0.0
        else:
            assert 0.0 < record["confidence"] <= 1.0


def test_the_demo_narrative_holds_ddos_is_caught_and_calm_traffic_is_not_a_high_alert(scored):
    _, records, _ = scored
    ddos = [r for r in records if r["actual_category"] == "DoS / DDoS"]
    assert ddos, "the demo CSV is expected to contain DDoS windows"
    assert all(r["risk_level"] == "High" and r["predicted_label"] == "DoS / DDoS" for r in ddos)

    calm = [r for r in records if r["actual_category"] == "Normal"]
    assert not any(r["risk_level"] == "High" for r in calm), "benign traffic must not raise High alerts"


def test_the_demo_flows_through_the_api_into_a_feedback_row_the_trainer_can_read(api, engine, monkeypatch, tmp_path):
    """ingest (real model) -> stored alert -> analyst feedback -> training CSV, on the real 76-feature schema."""
    from app.config import settings
    from app.routers import feedback as feedback_router, ingest as ingest_router

    monkeypatch.setattr(ingest_router, "get_engine", lambda: engine)
    monkeypatch.setattr(feedback_router, "get_engine", lambda: engine)
    monkeypatch.setattr(settings, "demo_csv", DEMO_CSV)

    login(api, "hunter@example.com")
    body = api.post("/api/ingest/demo").json()
    assert body["alerts_written"] == body["windows_scored"] > 0
    repeat = api.post("/api/ingest/demo").json()
    assert repeat["alerts_written"] == 0 and repeat["duplicates_skipped"] == body["windows_scored"]

    high = api.get("/api/alerts", params={"risk_level": "High", "batch_id": body["batch_id"]}).json()["items"][0]
    detail = api.get(f"/api/alerts/{high['id']}").json()
    assert len(detail["features"]) == 76 and detail["feature_schema_version"] == engine.feature_schema_version

    api.cookies.clear()
    login(api, "analyst@example.com")
    feedback = api.post("/api/feedback", json={"alert_id": high["id"], "validated_label": "DoS / DDoS"})
    assert feedback.status_code == 200 and feedback.json()["written_to_feedback_store"] is True

    training_rows = pd.read_csv(settings.feedback_store)
    assert list(training_rows.columns) == [*engine.feature_names, "Label"]
    assert len(training_rows) == 1 and training_rows.loc[0, "Label"] == "DoS / DDoS"
