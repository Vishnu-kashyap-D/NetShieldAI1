"""5.1 -- role enforcement: who may do what, checked for every role against every gated route."""
from __future__ import annotations

import pytest

from conftest import login, make_alert
from stub_engine import known_traffic_csv, make_engine

VIEWER, ANALYST, HUNTER, ADMIN = (f"{r}@example.com" for r in ("viewer", "analyst", "hunter", "admin"))
ALL = [VIEWER, ANALYST, HUNTER, ADMIN]


@pytest.fixture()
def gated(api, session_factory, monkeypatch):
    """The gated actions, each callable as `gated[name](client)` and made cheap and side-effect free:
    scoring uses the stub-model engine, and the retrain worker thread does nothing."""
    from app.routers import ingest as ingest_router, retrain as retrain_router

    monkeypatch.setattr(ingest_router, "get_engine", make_engine)
    monkeypatch.setattr(retrain_router, "_run_training", lambda run_id: None)
    alert_id = make_alert(session_factory)

    def csv_upload(client):
        return client.post("/api/ingest/csv", files={"file": ("known.csv", known_traffic_csv(), "text/csv")})

    return {
        "read alerts": lambda c: c.get("/api/alerts"),
        "read stats": lambda c: c.get("/api/stats/summary"),
        "read retrain history": lambda c: c.get("/api/retrain"),
        "read feedback": lambda c: c.get("/api/feedback"),
        "submit feedback": lambda c: c.post("/api/feedback", json={"alert_id": alert_id, "validated_label": "Normal"}),
        "ingest csv": csv_upload,
        "trigger retrain": lambda c: c.post("/api/retrain", json={}),
        "create user": lambda c: c.post(
            "/api/auth/users", json={"name": "N", "email": "new@example.com", "password": "longenough1", "role": "Viewer"}
        ),
        "list users": lambda c: c.get("/api/auth/users"),
    }


# action -> the roles allowed to perform it (mirrors the matrix in app/auth.py and backend/README.md)
ALLOWED = {
    "read alerts": ALL,
    "read stats": ALL,
    "read retrain history": ALL,
    "read feedback": ALL,
    "submit feedback": [ANALYST, HUNTER, ADMIN],
    "ingest csv": [HUNTER, ADMIN],
    "trigger retrain": [ADMIN],
    "create user": [ADMIN],
    "list users": [ADMIN],
}


@pytest.mark.parametrize("action", list(ALLOWED))
def test_every_role_gets_exactly_the_access_the_matrix_says(api, gated, action):
    for email in ALL:
        api.cookies.clear()
        login(api, email)
        status = gated[action](api).status_code
        if email in ALLOWED[action]:
            assert status < 300, f"{email} should be allowed to '{action}' but got {status}"
        else:
            assert status == 403, f"{email} should be forbidden to '{action}' but got {status}"


@pytest.mark.parametrize("action", list(ALLOWED))
def test_signed_out_requests_are_401_not_403(api, gated, action):
    """Authentication is checked before role, so a logged-out caller learns nothing about which roles a route wants."""
    assert gated[action](api).status_code == 401


def test_the_forbidden_message_names_the_required_roles_and_the_callers_role(api, gated):
    login(api, VIEWER)
    detail = gated["trigger retrain"](api).json()["detail"]
    assert "Administrator" in detail and "Viewer" in detail


def test_a_forbidden_action_has_no_side_effects(api, gated, session_factory):
    from sqlalchemy import func, select

    from app.models import TrainingRun, User

    login(api, ANALYST)
    assert gated["trigger retrain"](api).status_code == 403
    assert gated["create user"](api).status_code == 403
    with session_factory() as db:
        assert db.execute(select(func.count()).select_from(TrainingRun)).scalar_one() == 0
        assert db.execute(select(User).where(User.email == "new@example.com")).first() is None


def test_role_lives_on_the_account_not_in_the_request(api, gated):
    """There is no client-supplied role at login -- signing in as a Viewer can't be turned into an admin."""
    response = api.post("/api/auth/login", json={"email": VIEWER, "password": "pw-12345", "role": "Administrator"})
    assert response.json()["role"] == "Viewer"
    assert gated["trigger retrain"](api).status_code == 403


class TestAccountManagement:
    def test_an_admin_can_create_a_user_who_can_then_sign_in(self, api):
        login(api, ADMIN)
        created = api.post(
            "/api/auth/users",
            json={"name": "New Hunter", "email": "New.Hunter@Example.com", "password": "longenough1", "role": "Threat Hunter"},
        )
        assert created.status_code == 201
        assert created.json()["email"] == "new.hunter@example.com"  # normalised
        assert "password" not in created.text

        api.cookies.clear()
        response = api.post("/api/auth/login", json={"email": "new.hunter@example.com", "password": "longenough1"})
        assert response.status_code == 200 and response.json()["role"] == "Threat Hunter"

    def test_a_duplicate_email_is_a_409(self, api):
        login(api, ADMIN)
        payload = {"name": "X", "email": VIEWER, "password": "longenough1", "role": "Viewer"}
        assert api.post("/api/auth/users", json=payload).status_code == 409

    def test_an_unknown_role_is_rejected(self, api):
        login(api, ADMIN)
        payload = {"name": "X", "email": "x@example.com", "password": "longenough1", "role": "Superuser"}
        assert api.post("/api/auth/users", json=payload).status_code == 422

    def test_a_short_password_is_rejected(self, api):
        login(api, ADMIN)
        payload = {"name": "X", "email": "x@example.com", "password": "short", "role": "Viewer"}
        assert api.post("/api/auth/users", json=payload).status_code == 422

    def test_the_user_list_never_exposes_password_hashes(self, api):
        login(api, ADMIN)
        body = api.get("/api/auth/users").text
        assert "password" not in body and "$2b$" not in body

    def test_the_role_list_is_the_four_fixed_roles(self, api):
        login(api, VIEWER)
        assert api.get("/api/auth/roles").json() == ["Viewer", "Security Analyst", "Threat Hunter", "Administrator"]

    def test_the_role_list_needs_a_session(self, api):
        assert api.get("/api/auth/roles").status_code == 401
