"""4.5 -- every alert records which feature set it was scored under."""
from __future__ import annotations

from app.feature_schema import feature_schema_version
from conftest import FEATURES, login, make_alert


def test_version_ignores_order_but_not_membership():
    assert feature_schema_version(["a", "b", "c"]) == feature_schema_version(["c", "a", "b"])
    assert feature_schema_version(["a", "b", "c"]) != feature_schema_version(["a", "b"])
    assert feature_schema_version(["a", "b", "c"]) != feature_schema_version(["a", "b", "d"])
    assert len(feature_schema_version(FEATURES)) == 12


def test_alert_detail_exposes_the_version(api, session_factory):
    alert_id = make_alert(session_factory)
    login(api, "viewer@example.com")

    body = api.get(f"/api/alerts/{alert_id}").json()

    assert body["feature_schema_version"] == feature_schema_version(FEATURES)


def test_feedback_on_an_alert_from_a_different_feature_set_is_refused(api, session_factory):
    stale_id = make_alert(session_factory, features={"Flow Duration": 1.0, "Some Removed Feature": 2.0})
    login(api, "analyst@example.com")

    response = api.post("/api/feedback", json={"alert_id": stale_id, "validated_label": "DoS / DDoS"})

    assert response.status_code == 409
    assert "feature set" in response.json()["detail"]
    assert not api.feedback_csv.exists()  # nothing was written as a training row


def test_feedback_on_an_unversioned_legacy_alert_still_works(api, session_factory):
    legacy_id = make_alert(session_factory, schema_version=None)
    login(api, "analyst@example.com")

    assert api.post("/api/feedback", json={"alert_id": legacy_id, "validated_label": "DoS / DDoS"}).status_code == 200
