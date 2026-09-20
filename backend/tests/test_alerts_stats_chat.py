"""5.1 -- read endpoints (alerts, stats, model metrics) and the chatbots' limits and degradation."""
from __future__ import annotations

import json

import pytest

from conftest import login, make_alert
from app.config import settings
from app.models import Alert

VIEWER = "viewer@example.com"


# --- alerts ----------------------------------------------------------------------------------------


@pytest.fixture()
def seeded(api, session_factory):
    """Three alerts with different levels/labels/sources/batches, and a Viewer signed in."""
    login(api, VIEWER)
    ids = {}
    for key, (level, label, source, batch) in {
        "high": ("High", "DoS / DDoS", "mon.csv", "1" * 36),
        "medium": ("Medium", "Port Scanning", "mon.csv", "1" * 36),
        "other": ("High", "Botnet Activity", "tue.csv", "2" * 36),
    }.items():
        alert_id = make_alert(session_factory)
        with session_factory() as db:
            alert = db.get(Alert, alert_id)
            alert.risk_level, alert.predicted_label, alert.source_file, alert.batch_id = level, label, source, batch
            db.commit()
        ids[key] = alert_id
    return ids


def test_alerts_can_be_filtered(api, seeded):
    def ids_for(**params):
        return {a["id"] for a in api.get("/api/alerts", params=params).json()["items"]}

    assert ids_for(risk_level="High") == {seeded["high"], seeded["other"]}
    assert ids_for(category="Port Scanning") == {seeded["medium"]}
    assert ids_for(source_file="tue.csv") == {seeded["other"]}
    assert ids_for(batch_id="1" * 36) == {seeded["high"], seeded["medium"]}
    assert ids_for(risk_level="High", source_file="mon.csv") == {seeded["high"]}
    assert ids_for(risk_level="Low") == set()


def test_alerts_are_paginated_newest_first_with_a_total(api, seeded):
    page = api.get("/api/alerts", params={"limit": 2, "offset": 0}).json()
    assert page["total"] == 3 and len(page["items"]) == 2
    assert [a["id"] for a in page["items"]] == sorted((a["id"] for a in page["items"]), reverse=True)
    rest = api.get("/api/alerts", params={"limit": 2, "offset": 2}).json()
    assert len(rest["items"]) == 1
    assert {a["id"] for a in page["items"]} | {a["id"] for a in rest["items"]} == set(seeded.values())


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 501}, {"offset": -1}])
def test_out_of_range_paging_is_a_422(api, seeded, params):
    assert api.get("/api/alerts", params=params).status_code == 422


def test_alert_detail_includes_the_feature_vector_and_404s_for_unknown_ids(api, seeded):
    detail = api.get(f"/api/alerts/{seeded['high']}").json()
    assert detail["risk_level"] == "High" and set(detail["features"]) == {"Flow Duration", "Total Fwd Packets", "Flow Bytes/s"}
    assert api.get("/api/alerts/99999").status_code == 404


def test_the_list_view_omits_the_heavy_feature_vector(api, seeded):
    assert "features" not in api.get("/api/alerts").json()["items"][0]


# --- stats -----------------------------------------------------------------------------------------


def test_summary_counts_by_level_and_category(api, seeded):
    body = api.get("/api/stats/summary").json()
    assert body["total_alerts"] == 3
    assert body["risk_level_counts"] == {"High": 2, "Medium": 1}
    assert body["category_counts"] == {"DoS / DDoS": 1, "Port Scanning": 1, "Botnet Activity": 1}
    assert body["anomaly_count"] == 3


def test_summary_on_an_empty_database_is_all_zeros(api):
    login(api, VIEWER)
    assert api.get("/api/stats/summary").json() == {
        "total_alerts": 0, "risk_level_counts": {}, "category_counts": {}, "anomaly_count": 0,
    }


def test_model_metrics_are_read_from_the_last_training_report(api, tmp_path, monkeypatch):
    class_row = {"precision": 0.9, "recall": 0.8, "f1-score": 0.85, "support": 40}
    report = {
        "bilstm_classifier": {
            "classification_report": {
                "DoS / DDoS": class_row, "accuracy": 0.97,
                "macro avg": {"f1-score": 0.9}, "weighted avg": {"f1-score": 0.95},
            }
        },
        "autoencoder": {
            "classification_report": {"accuracy": 0.93},
            "threshold_report": {"balanced_accuracy": 0.94, "true_positive_rate": 0.92, "true_negative_rate": 0.96},
        },
        "hybrid_risk": {"false_positive_rate": 0.02, "false_negative_rate": 0.11},
    }
    (tmp_path / "training_metrics.json").write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(settings, "reports_dir", tmp_path)
    login(api, VIEWER)

    body = api.get("/api/stats/model-metrics").json()
    assert body["bilstm_accuracy"] == 0.97 and body["bilstm_macro_f1"] == 0.9
    assert body["autoencoder_balanced_accuracy"] == 0.94
    assert body["hybrid_false_negative_rate"] == 0.11
    # the summary rows ("accuracy", "macro avg", ...) are not classes
    assert [c["category"] for c in body["bilstm_per_class"]] == ["DoS / DDoS"]


def test_model_metrics_404_when_no_report_exists(api, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "reports_dir", tmp_path)
    login(api, VIEWER)
    assert api.get("/api/stats/model-metrics").status_code == 404


# --- chatbots --------------------------------------------------------------------------------------


@pytest.fixture()
def no_llm(monkeypatch):
    """No Gemini key configured (the safe default): the LLM can't be reached."""
    monkeypatch.setattr(settings, "gemini_api_key", None)


def test_a_viewer_can_use_both_chatbots(api, seeded, no_llm):
    assert api.post(f"/api/alerts/{seeded['high']}/chat", json={"question": "What is the confidence?"}).status_code == 200
    assert api.post("/api/chat", json={"question": "What is CICIDS2017?"}).status_code == 200


def test_the_per_alert_bot_answers_numeric_questions_without_any_llm(api, seeded, no_llm):
    answer = api.post(f"/api/alerts/{seeded['high']}/chat", json={"question": "What is the confidence?"}).json()
    assert "99.0%" in answer["answer"]          # the stored confidence (0.99), quoted, not invented
    assert answer["sources"]["prediction"] is True


def test_open_ended_questions_degrade_to_an_honest_unavailable_message(api, seeded, no_llm):
    for response in (
        api.post(f"/api/alerts/{seeded['high']}/chat", json={"question": "Explain this to a five year old"}),
        api.post("/api/chat", json={"question": "Tell me about port scanning"}),
    ):
        assert response.status_code == 200
        answer = response.json()["answer"].lower()
        assert "unavailable" in answer or "isn't available" in answer  # says so plainly; no crash, no invented answer


def test_chatting_about_a_missing_alert_is_404(api, no_llm):
    login(api, VIEWER)
    assert api.post("/api/alerts/12345/chat", json={"question": "hi"}).status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {"question": "x" * 2001},                                               # question too long
        {"question": "q", "history": [{"role": "user", "content": "x"}] * 41},  # too many turns
        {"question": "q", "history": [{"role": "user", "content": "x" * 8001}]},  # one message too long
    ],
    ids=["long-question", "long-history", "long-message"],
)
def test_oversized_chat_input_is_rejected_before_it_can_reach_a_paid_llm(api, seeded, no_llm, body):
    assert api.post("/api/chat", json=body).status_code == 422
    assert api.post(f"/api/alerts/{seeded['high']}/chat", json=body).status_code == 422


def test_the_chat_budget_is_per_user_and_shared_by_both_bots(api, seeded, no_llm, monkeypatch):
    from app.ratelimit import SlidingWindowLimiter
    from app.routers import chat as chat_router

    monkeypatch.setattr(chat_router, "_chat_limiter", SlidingWindowLimiter(3, 60))
    alert = f"/api/alerts/{seeded['high']}/chat"
    assert api.post(alert, json={"question": "confidence?"}).status_code == 200
    assert api.post("/api/chat", json={"question": "hi"}).status_code == 200
    assert api.post(alert, json={"question": "confidence?"}).status_code == 200

    blocked = api.post("/api/chat", json={"question": "hi"})
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) > 0

    api.cookies.clear()
    login(api, "analyst@example.com")  # somebody else has their own budget
    assert api.post("/api/chat", json={"question": "hi"}).status_code == 200


def test_the_alert_chat_context_holds_only_that_alerts_own_data(seeded, session_factory):
    """The chatbot (and the LLM behind it) may reason only from this dict -- no credentials, no other alerts."""
    from app.chat_service import build_alert_context

    with session_factory() as db:
        context = build_alert_context(db.get(Alert, seeded["high"]))
    assert context["alert_id"] == seeded["high"] and context["risk_level"] == "High"
    text = json.dumps(context, default=str).lower()
    for forbidden in ("password", "token", "secret", "api_key", "mon.csv", "botnet"):
        assert forbidden not in text
