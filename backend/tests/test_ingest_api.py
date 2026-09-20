"""5.1 -- POST /api/ingest/csv end to end (upload -> score -> store -> report), on a known CSV."""
from __future__ import annotations

import pytest
from sqlalchemy import func, select

from conftest import login
from app.config import settings
from app.models import Alert
from stub_engine import known_traffic_csv, make_engine

HUNTER = "hunter@example.com"


@pytest.fixture()
def ingest(api, session_factory, monkeypatch):
    from app.routers import ingest as ingest_router

    monkeypatch.setattr(ingest_router, "get_engine", make_engine)
    login(api, HUNTER)

    def upload(content: bytes | None = None, name: str = "known.csv", **params):
        content = known_traffic_csv() if content is None else content
        return api.post("/api/ingest/csv", params=params, files={"file": (name, content, "text/csv")})

    upload.client = api
    upload.count = lambda: _alert_count(session_factory)
    return upload


def _alert_count(session_factory) -> int:
    with session_factory() as db:
        return db.execute(select(func.count()).select_from(Alert)).scalar_one()


def test_a_known_csv_produces_the_expected_summary(ingest):
    response = ingest()
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "known.csv"
    assert body["windows_scored"] == 4
    assert body["anomalous_windows"] == 2
    assert body["alerts_written"] == 2          # Low-risk windows are not stored by default
    assert body["duplicates_skipped"] == 0
    # the counts describe what was *stored* (Medium + High), not everything that was scored
    assert body["risk_level_counts"] == {"Medium": 1, "High": 1}
    assert body["predicted_label_counts"] == {"DoS / DDoS": 1, "Port Scanning": 1}


def test_stored_alerts_match_the_summary_and_are_queryable(ingest):
    batch_id = ingest().json()["batch_id"]
    listing = ingest.client.get("/api/alerts", params={"batch_id": batch_id}).json()
    assert listing["total"] == 2
    by_level = {item["risk_level"]: item for item in listing["items"]}
    assert by_level["High"]["predicted_label"] == "Port Scanning"
    assert by_level["Medium"]["predicted_label"] == "DoS / DDoS"
    assert by_level["High"]["window_start"] == 30 and by_level["High"]["window_end"] == 39

    summary = ingest.client.get("/api/stats/summary").json()
    assert summary["total_alerts"] == 2
    assert summary["risk_level_counts"] == {"Medium": 1, "High": 1}
    assert summary["anomaly_count"] == 2


def test_include_all_windows_stores_the_low_risk_windows_as_well(ingest):
    body = ingest(include_all_windows="true").json()
    assert body["alerts_written"] == 4
    assert body["risk_level_counts"] == {"Low": 2, "Medium": 1, "High": 1}


def test_uploading_the_same_file_twice_stores_nothing_new(ingest):
    first = ingest().json()
    second = ingest().json()
    assert second["batch_id"] == first["batch_id"]
    assert second["alerts_written"] == 0
    assert second["duplicates_skipped"] == 2
    assert ingest.count() == 2


def test_the_same_bytes_under_another_name_are_new_data(ingest):
    ingest(name="a.csv")
    other = ingest(name="b.csv").json()
    assert other["alerts_written"] == 2
    assert ingest.count() == 4


def test_a_different_file_with_the_same_name_is_new_data(ingest):
    ingest(name="same.csv")
    changed = known_traffic_csv().replace(b"PortScan", b"DDoS")
    assert ingest(changed, name="same.csv").json()["alerts_written"] == 2
    assert ingest.count() == 4


def test_a_later_pass_with_include_all_adds_only_the_windows_the_first_pass_skipped(ingest):
    ingest()
    body = ingest(include_all_windows="true").json()
    assert body["alerts_written"] == 2 and body["duplicates_skipped"] == 2
    assert ingest.count() == 4


def test_allow_duplicates_stores_a_replay_as_a_new_batch(ingest):
    first = ingest(allow_duplicates="true").json()
    second = ingest(allow_duplicates="true").json()
    assert second["batch_id"] != first["batch_id"]
    assert second["alerts_written"] == 2
    assert ingest.count() == 4


def test_a_file_over_the_size_limit_is_413(ingest, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 100)
    response = ingest()
    assert response.status_code == 413
    assert ingest.count() == 0


@pytest.mark.parametrize(
    "content",
    [b"", b"\x00\x01\x02\xff\xfe binary garbage", b"just,one,header\n"],
    ids=["empty", "binary", "header-only"],
)
def test_an_unusable_upload_is_a_clean_422_not_a_500(ingest, content):
    assert ingest(content).status_code == 422


def test_a_csv_too_short_for_a_single_window_is_a_422(ingest):
    short = b"Flow Duration,Total Fwd Packets,Flow Bytes/s\n" + b"1,1,1\n" * 5
    response = ingest(short)
    assert response.status_code == 422
    assert "window" in response.json()["detail"].lower()
    assert ingest.count() == 0


def test_a_missing_file_field_is_a_422(ingest):
    assert ingest.client.post("/api/ingest/csv").status_code == 422


def test_the_ingest_demo_endpoint_scores_the_configured_csv(ingest, monkeypatch, tmp_path):
    demo = tmp_path / "demo.csv"
    demo.write_bytes(known_traffic_csv())
    monkeypatch.setattr(settings, "demo_csv", demo)
    body = ingest.client.post("/api/ingest/demo").json()
    assert body["source"] == "demo.csv"
    assert body["alerts_written"] == 4          # the demo defaults to storing every window
    assert ingest.client.post("/api/ingest/demo").json()["alerts_written"] == 0  # and is idempotent


def test_the_ingest_demo_endpoint_404s_when_the_file_is_missing(ingest, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "demo_csv", tmp_path / "nope.csv")
    assert ingest.client.post("/api/ingest/demo").status_code == 404
