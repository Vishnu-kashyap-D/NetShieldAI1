"""6.1 -- the "Unknown" option: flagged windows the classifier isn't confident about are not forced into a category."""
from __future__ import annotations

import io

import numpy as np
import pytest

from conftest import login, make_alert
from app.detection_service import load_csv_as_traffic_frame
from cyber_ai.hybrid_risk import apply_abstention
from stub_engine import known_traffic_csv, make_engine

UNKNOWN = "Unknown"


def _score(threshold, **kwargs):
    frame = load_csv_as_traffic_frame(io.BytesIO(known_traffic_csv()), source_name="known.csv")
    return make_engine(threshold).score_dataframe(frame, include_all_windows=True, **kwargs)


class TestApplyAbstention:
    labels = np.array(["Normal", "DoS / DDoS", "Port Scanning", "Botnet Activity"], dtype=object)
    confidences = np.array([0.0, 0.6, 0.95, 0.85])
    classified = np.array([False, True, True, True])

    def test_low_confidence_classified_windows_become_unknown(self):
        labels, abstained = apply_abstention(self.labels, self.confidences, self.classified, 0.9)
        assert labels.tolist() == ["Normal", UNKNOWN, "Port Scanning", UNKNOWN]
        assert abstained.tolist() == [False, True, False, True]

    def test_the_threshold_boundary_keeps_the_label(self):
        labels, _ = apply_abstention(self.labels, np.array([0.0, 0.9, 0.9, 0.9]), self.classified, 0.9)
        assert labels.tolist()[1:] == ["DoS / DDoS", "Port Scanning", "Botnet Activity"]

    @pytest.mark.parametrize("off", [None, 0, 0.0])
    def test_no_threshold_means_no_change(self, off):
        labels, abstained = apply_abstention(self.labels, self.confidences, self.classified, off)
        assert labels.tolist() == self.labels.tolist() and not abstained.any()

    def test_windows_the_classifier_never_saw_are_never_relabelled(self):
        # "Normal" has confidence 0.0, which is below any threshold -- but it was never classified.
        labels, abstained = apply_abstention(self.labels, self.confidences, self.classified, 0.99)
        assert labels[0] == "Normal" and not abstained[0]

    def test_the_input_array_is_not_mutated(self):
        original = self.labels.copy()
        apply_abstention(self.labels, self.confidences, self.classified, 0.9)
        assert self.labels.tolist() == original.tolist()


class TestScoringWithAbstention:
    """Stand-in classifier: window 20 -> DoS / DDoS at 0.6 confidence, window 30 -> Port Scanning at 0.9."""

    def test_off_by_default_every_flagged_window_gets_a_category(self):
        records, summary = _score(None)
        assert [r["predicted_label"] for r in records] == ["Normal", "Normal", "DoS / DDoS", "Port Scanning"]
        assert UNKNOWN not in summary["predicted_label_counts"]

    def test_a_threshold_relabels_only_the_unsure_window(self):
        records, summary = _score(0.7)
        assert [r["predicted_label"] for r in records] == ["Normal", "Normal", UNKNOWN, "Port Scanning"]
        assert summary["predicted_label_counts"] == {"Normal": 2, UNKNOWN: 1, "Port Scanning": 1}

    def test_only_the_label_changes_never_the_scores_or_the_risk_level(self):
        before, _ = _score(None)
        after, _ = _score(0.7)
        for old, new in zip(before, after):
            for field in ("confidence", "anomaly_score", "risk_score", "risk_level", "is_anomaly", "window_start"):
                assert old[field] == new[field], field

    def test_the_pipeline_action_says_why_the_window_is_unknown(self):
        records, _ = _score(0.7)
        assert [r["pipeline_action"] for r in records] == [
            "Ignored as normal", "Ignored as normal",
            "Flagged as anomalous, category unknown", "Classified and alerted",
        ]

    def test_a_threshold_of_one_leaves_no_window_named(self):
        records, _ = _score(1.0)
        assert [r["predicted_label"] for r in records if r["is_anomaly"]] == [UNKNOWN, UNKNOWN]


class TestConfiguration:
    def test_it_is_off_unless_configured(self, monkeypatch):
        from app.config import Settings

        monkeypatch.delenv("UNKNOWN_CONFIDENCE_THRESHOLD", raising=False)
        assert Settings(_env_file=None).unknown_confidence_threshold is None

    def test_it_is_read_from_the_environment(self, monkeypatch):
        from app.config import Settings

        monkeypatch.setenv("UNKNOWN_CONFIDENCE_THRESHOLD", "0.9")
        assert Settings(_env_file=None).unknown_confidence_threshold == 0.9

    @pytest.mark.parametrize("bad", ["1.5", "-0.1", "high"])
    def test_a_nonsense_value_fails_at_startup(self, monkeypatch, bad):
        from app.config import Settings

        monkeypatch.setenv("UNKNOWN_CONFIDENCE_THRESHOLD", bad)
        with pytest.raises(Exception):
            Settings(_env_file=None)


class TestUnknownAlertsThroughTheApi:
    @pytest.fixture()
    def ingested(self, api, monkeypatch):
        from app.routers import ingest as ingest_router

        monkeypatch.setattr(ingest_router, "get_engine", lambda: make_engine(0.7))
        login(api, "hunter@example.com")
        body = api.post("/api/ingest/csv", files={"file": ("k.csv", known_traffic_csv(), "text/csv")}).json()
        api.cookies.clear()
        return body

    def test_unknown_alerts_are_stored_filterable_and_counted(self, api, ingested):
        assert ingested["predicted_label_counts"] == {UNKNOWN: 1, "Port Scanning": 1}
        login(api, "viewer@example.com")
        items = api.get("/api/alerts", params={"category": UNKNOWN}).json()["items"]
        assert len(items) == 1 and items[0]["pipeline_action"] == "Flagged as anomalous, category unknown"
        assert api.get("/api/stats/summary").json()["category_counts"] == {UNKNOWN: 1, "Port Scanning": 1}

    def test_an_analyst_cannot_validate_an_alert_as_unknown(self, api, session_factory):
        alert_id = make_alert(session_factory)
        login(api, "analyst@example.com")
        response = api.post("/api/feedback", json={"alert_id": alert_id, "validated_label": UNKNOWN})
        assert response.status_code == 422 and "Unknown" in response.json()["detail"]
        assert not api.feedback_csv.exists()                       # nothing reached the training data
        assert api.get("/api/feedback").json() == []               # ...or the feedback table

    def test_an_unknown_alert_can_still_be_resolved_to_a_real_category(self, api, session_factory):
        alert_id = make_alert(session_factory)
        login(api, "analyst@example.com")
        assert api.post("/api/feedback", json={"alert_id": alert_id, "validated_label": "Normal"}).status_code == 200


class TestChatbotOnUnknownAlerts:
    @pytest.fixture()
    def unknown_alert(self, api, session_factory, monkeypatch):
        from app.config import settings
        from app.models import Alert

        monkeypatch.setattr(settings, "gemini_api_key", None)
        alert_id = make_alert(session_factory)
        with session_factory() as db:
            alert = db.get(Alert, alert_id)
            alert.predicted_label, alert.confidence = UNKNOWN, 0.62
            alert.pipeline_action = "Flagged as anomalous, category unknown"
            db.commit()
        login(api, "viewer@example.com")
        return alert_id

    def _ask(self, api, alert_id, question):
        return api.post(f"/api/alerts/{alert_id}/chat", json={"question": question}).json()["answer"]

    def test_why_classified_explains_the_abstention_instead_of_claiming_a_category(self, api, unknown_alert):
        answer = self._ask(api, unknown_alert, "Why was this classified this way?")
        assert "Unknown" in answer and "62.0%" in answer
        assert "classified as Unknown" not in answer

    def test_the_confidence_answer_does_not_present_unknown_as_a_predicted_class(self, api, unknown_alert):
        answer = self._ask(api, unknown_alert, "How confident was the model?")
        assert "62.0%" in answer and "predicted class (Unknown)" not in answer
