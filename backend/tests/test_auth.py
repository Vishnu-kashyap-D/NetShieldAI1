"""5.1 -- login / logout / sessions / lockout."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select

from conftest import login
from app.config import settings
from app.models import UserSession


def _cookie(client):
    return client.cookies.get(settings.session_cookie_name)


def test_login_returns_the_account_and_sets_an_httponly_session_cookie(api):
    response = api.post("/api/auth/login", json={"email": "analyst@example.com", "password": "pw-12345"})
    assert response.status_code == 200
    assert response.json() == {"id": 1, "name": "analyst", "email": "analyst@example.com", "role": "Security Analyst"}
    set_cookie = response.headers["set-cookie"]
    assert f"{settings.session_cookie_name}=" in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()


def test_email_is_case_insensitive(api):
    response = api.post("/api/auth/login", json={"email": "Analyst@Example.COM", "password": "pw-12345"})
    assert response.status_code == 200


def test_wrong_password_and_unknown_user_look_identical(api):
    """Distinguishing them would let an attacker enumerate which emails have accounts."""
    wrong_password = api.post("/api/auth/login", json={"email": "analyst@example.com", "password": "nope"})
    no_such_user = api.post("/api/auth/login", json={"email": "ghost@example.com", "password": "nope"})
    assert wrong_password.status_code == no_such_user.status_code == 401
    assert wrong_password.json() == no_such_user.json()


def test_a_failed_login_sets_no_cookie(api):
    response = api.post("/api/auth/login", json={"email": "analyst@example.com", "password": "nope"})
    assert "set-cookie" not in response.headers


def test_an_oversized_password_is_rejected_before_it_reaches_bcrypt(api):
    response = api.post("/api/auth/login", json={"email": "analyst@example.com", "password": "x" * 129})
    assert response.status_code == 422


def test_protected_routes_need_a_session(api):
    for path in ["/api/auth/me", "/api/alerts", "/api/stats/summary", "/api/feedback", "/api/retrain"]:
        assert api.get(path).status_code == 401, path


def test_me_returns_the_signed_in_user(api):
    login(api, "viewer@example.com")
    assert api.get("/api/auth/me").json()["role"] == "Viewer"


def test_logout_really_ends_the_session(api):
    login(api, "analyst@example.com")
    stolen_copy = _cookie(api)
    assert api.post("/api/auth/logout").json() == {"status": "signed_out"}

    api.cookies.set(settings.session_cookie_name, stolen_copy)  # replay the old cookie
    assert api.get("/api/auth/me").status_code == 401


def test_logout_without_a_session_is_a_401(api):
    assert api.post("/api/auth/logout").status_code == 401


def test_logging_out_one_browser_leaves_the_users_other_sessions_alone(api, session_factory):
    login(api, "analyst@example.com")
    first = _cookie(api)
    login(api, "analyst@example.com")  # a second sign-in, e.g. another device
    second = _cookie(api)
    assert first != second

    api.post("/api/auth/logout")  # signs out `second`
    api.cookies.set(settings.session_cookie_name, first)
    assert api.get("/api/auth/me").status_code == 200


def test_only_a_hash_of_the_session_token_is_stored(api, session_factory):
    login(api, "analyst@example.com")
    raw = _cookie(api)
    with session_factory() as db:
        stored = db.execute(select(UserSession.token)).scalars().all()
    assert raw not in stored          # a leaked sessions table can't be replayed as a cookie
    assert len(stored[0]) == 64       # sha256 hex


def test_a_tampered_cookie_is_rejected(api):
    login(api, "analyst@example.com")
    api.cookies.set(settings.session_cookie_name, _cookie(api) + "x")
    assert api.get("/api/auth/me").status_code == 401


def test_an_expired_session_is_rejected_and_removed(api, session_factory):
    login(api, "analyst@example.com")
    with session_factory() as db:
        row = db.execute(select(UserSession)).scalar_one()
        row.expires_at = dt.datetime.utcnow() - dt.timedelta(seconds=1)
        db.commit()

    response = api.get("/api/auth/me")
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()
    with session_factory() as db:
        assert db.execute(select(UserSession)).first() is None


# --- login lockout ---------------------------------------------------------------------------------


def _fail(client, email="analyst@example.com"):
    return client.post("/api/auth/login", json={"email": email, "password": "wrong"})


def test_five_failures_lock_the_account_with_a_retry_after(api):
    for _ in range(settings.login_max_failures):
        assert _fail(api).status_code == 401
    blocked = _fail(api)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0


def test_the_lockout_applies_even_to_the_correct_password(api):
    for _ in range(settings.login_max_failures):
        _fail(api)
    response = api.post("/api/auth/login", json={"email": "analyst@example.com", "password": "pw-12345"})
    assert response.status_code == 429


def test_locking_one_account_does_not_lock_another(api):
    for _ in range(settings.login_max_failures):
        _fail(api, "analyst@example.com")
    assert api.post("/api/auth/login", json={"email": "viewer@example.com", "password": "pw-12345"}).status_code == 200


def test_a_successful_login_clears_the_failure_count(api):
    for _ in range(settings.login_max_failures - 1):
        _fail(api)
    login(api, "analyst@example.com")
    for _ in range(settings.login_max_failures - 1):  # would exceed the limit if the earlier ones still counted
        assert _fail(api).status_code == 401


def test_being_blocked_does_not_extend_the_lockout(api):
    from app.routers import auth as auth_router

    for _ in range(settings.login_max_failures):
        _fail(api)
    key = "testclient|analyst@example.com"
    before = len(auth_router._login_account_limiter._events[key])
    for _ in range(5):
        assert _fail(api).status_code == 429
    assert len(auth_router._login_account_limiter._events[key]) == before


def test_one_address_spraying_many_emails_is_stopped_by_the_per_ip_limit(api):
    for n in range(settings.login_ip_max_failures):
        assert _fail(api, f"user{n}@example.com").status_code == 401  # each email fails once: per-account limit never trips
    assert _fail(api, "fresh@example.com").status_code == 429


def test_the_forwarded_for_header_cannot_be_used_to_dodge_the_limit(api):
    for n in range(settings.login_max_failures):
        api.post(
            "/api/auth/login",
            json={"email": "analyst@example.com", "password": "wrong"},
            headers={"X-Forwarded-For": f"10.0.0.{n}"},
        )
    response = api.post(
        "/api/auth/login",
        json={"email": "analyst@example.com", "password": "wrong"},
        headers={"X-Forwarded-For": "10.9.9.9"},
    )
    assert response.status_code == 429
