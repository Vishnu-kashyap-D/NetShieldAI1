"""4.1 -- one validated label per alert; resubmitting updates instead of stacking rows."""
from __future__ import annotations

import csv

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from conftest import FEATURES, login, make_alert


def _csv_rows(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _feedback_count(session_factory, alert_id):
    from app.models import Feedback

    with session_factory() as db:
        return db.execute(select(func.count()).select_from(Feedback).where(Feedback.alert_id == alert_id)).scalar_one()


def test_first_submission_creates_one_row_and_one_training_line(api, session_factory):
    alert_id = make_alert(session_factory)
    login(api, "analyst@example.com")

    response = api.post("/api/feedback", json={"alert_id": alert_id, "validated_label": "DoS / DDoS"})

    assert response.status_code == 200
    assert response.json()["written_to_feedback_store"] is True
    assert _feedback_count(session_factory, alert_id) == 1
    rows = _csv_rows(api.feedback_csv)
    assert len(rows) == 1 and rows[0]["Label"] == "DoS / DDoS"
    assert list(rows[0].keys()) == [*FEATURES, "Label"]


def test_resubmitting_the_same_label_is_idempotent(api, session_factory):
    alert_id = make_alert(session_factory)
    login(api, "analyst@example.com")
    body = {"alert_id": alert_id, "validated_label": "DoS / DDoS"}

    first = api.post("/api/feedback", json=body).json()
    second = api.post("/api/feedback", json=body).json()

    assert second["id"] == first["id"]
    assert _feedback_count(session_factory, alert_id) == 1
    assert len(_csv_rows(api.feedback_csv)) == 1  # not a second, identical training row


def test_correcting_the_label_updates_the_row_and_replaces_the_training_line(api, session_factory):
    alert_id = make_alert(session_factory)
    other_id = make_alert(session_factory, features={name: 99.0 for name in FEATURES})
    login(api, "analyst@example.com")
    api.post("/api/feedback", json={"alert_id": alert_id, "validated_label": "DoS / DDoS"})
    api.post("/api/feedback", json={"alert_id": other_id, "validated_label": "Port Scanning"})

    response = api.post(
        "/api/feedback", json={"alert_id": alert_id, "validated_label": "Botnet Activity", "notes": "reviewed again"}
    )

    assert response.status_code == 200
    assert response.json()["validated_label"] == "Botnet Activity"
    assert _feedback_count(session_factory, alert_id) == 1
    rows = _csv_rows(api.feedback_csv)
    # still exactly one line per alert: the stale "DoS / DDoS" line is gone, the other alert's is untouched
    assert sorted(row["Label"] for row in rows) == ["Botnet Activity", "Port Scanning"]


def test_replacing_a_line_preserves_the_files_own_line_endings(api, session_factory):
    alert_id = make_alert(session_factory)
    login(api, "analyst@example.com")
    api.post("/api/feedback", json={"alert_id": alert_id, "validated_label": "DoS / DDoS"})
    api.post("/api/feedback", json={"alert_id": alert_id, "validated_label": "Botnet Activity"})

    raw = api.feedback_csv.read_bytes()
    assert raw.count(b"\r\n") == 2  # header + the one data row, both still \r\n
    assert raw.replace(b"\r\n", b"").count(b"\n") == 0


def test_database_rejects_a_second_feedback_row_for_the_same_alert(session_factory):
    from app.models import Feedback

    alert_id = make_alert(session_factory)
    with session_factory() as db:
        db.add(Feedback(alert_id=alert_id, validated_label="A"))
        db.commit()
        db.add(Feedback(alert_id=alert_id, validated_label="B"))
        with pytest.raises(IntegrityError):
            db.commit()


def test_unknown_alert_is_404(api):
    login(api, "analyst@example.com")
    assert api.post("/api/feedback", json={"alert_id": 9999, "validated_label": "X"}).status_code == 404


def test_viewer_cannot_submit_feedback(api, session_factory):
    alert_id = make_alert(session_factory)
    login(api, "viewer@example.com")
    assert api.post("/api/feedback", json={"alert_id": alert_id, "validated_label": "X"}).status_code == 403
    assert _feedback_count(session_factory, alert_id) == 0


def test_an_unfinished_earlier_attempt_is_completed_on_retry(api, session_factory):
    """Row saved but the CSV write never happened (flag False) -> the retry writes the training line."""
    from app.models import Feedback

    alert_id = make_alert(session_factory)
    with session_factory() as db:
        db.add(Feedback(alert_id=alert_id, validated_label="DoS / DDoS", written_to_feedback_store=False))
        db.commit()
    login(api, "analyst@example.com")

    api.post("/api/feedback", json={"alert_id": alert_id, "validated_label": "DoS / DDoS"})

    assert len(_csv_rows(api.feedback_csv)) == 1
    assert _feedback_count(session_factory, alert_id) == 1
