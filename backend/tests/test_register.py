"""Public self-registration: POST /api/auth/register."""
from __future__ import annotations

from sqlalchemy import select

from app.config import settings
from app.models import User
from app.routers import auth as auth_router


def _signup(client, email="new.person@example.com", password="pw-12345", name="New Person", **extra):
    return client.post("/api/auth/register", json={"name": name, "email": email, "password": password, **extra})


def test_signup_creates_a_viewer_and_signs_them_in(api):
    response = _signup(api)
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new.person@example.com"
    assert body["role"] == "Viewer"
    assert settings.session_cookie_name in response.headers["set-cookie"]

    me = api.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "new.person@example.com"


def test_the_new_account_can_sign_in_again_later(api):
    _signup(api)
    api.post("/api/auth/logout")
    response = api.post("/api/auth/login", json={"email": "new.person@example.com", "password": "pw-12345"})
    assert response.status_code == 200
    assert response.json()["role"] == "Viewer"


def test_a_requested_role_is_ignored(api):
    """A visitor must never be able to grant themselves a role."""
    response = _signup(api, role="Administrator")
    assert response.status_code == 201
    assert response.json()["role"] == "Viewer"


def test_a_self_registered_viewer_cannot_do_privileged_things(api):
    _signup(api)
    assert api.post("/api/retrain").status_code == 403
    assert api.get("/api/auth/users").status_code == 403


def test_email_is_stored_lowercase_and_duplicates_are_case_insensitive(api, session_factory):
    assert _signup(api, email="Mixed.Case@Example.com").status_code == 201
    api.cookies.clear()
    duplicate = _signup(api, email="mixed.case@example.COM")
    assert duplicate.status_code == 409
    assert "set-cookie" not in duplicate.headers
    with session_factory() as db:
        emails = db.execute(select(User.email).where(User.email.like("%mixed%"))).scalars().all()
    assert emails == ["mixed.case@example.com"]


def test_signing_up_with_a_seeded_accounts_email_is_refused(api):
    assert _signup(api, email="analyst@example.com").status_code == 409


def test_two_signups_racing_for_the_same_email_give_a_409_not_a_500(api, session_factory, monkeypatch):
    """Simulates another request inserting the same email between this request's duplicate check and
    its commit -- only the database's unique index can catch that."""
    real_hash = auth_router.hash_password

    def hash_then_lose_the_race(password: str) -> str:
        with session_factory() as other:
            other.add(User(name="Racer", email="race@example.com", password_hash=real_hash(password), role="Viewer"))
            other.commit()
        return real_hash(password)

    monkeypatch.setattr(auth_router, "hash_password", hash_then_lose_the_race)
    response = _signup(api, email="race@example.com")
    assert response.status_code == 409
    assert response.json()["detail"] == "An account with this email already exists."


def test_weak_or_malformed_input_is_rejected(api):
    assert _signup(api, password="short").status_code == 422
    assert _signup(api, password="x" * 129).status_code == 422
    assert _signup(api, email="not-an-email").status_code == 422
    assert _signup(api, name="").status_code == 422
    assert _signup(api, name="   ").status_code == 422


def test_the_name_is_trimmed(api):
    assert _signup(api, name="  Padded Name  ").json()["name"] == "Padded Name"


def test_every_attempt_counts_toward_the_per_ip_limit(api):
    """Failures count too -- otherwise duplicate-email probing would be unthrottled."""
    limit = settings.register_ip_max_attempts
    for i in range(limit):
        email = "analyst@example.com" if i % 2 else f"user{i}@example.com"  # mix of successes and 409s
        api.cookies.clear()
        assert _signup(api, email=email).status_code in (201, 409)

    blocked = _signup(api, email="one.more@example.com")
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    assert "Try again in" in blocked.json()["detail"]


def test_signup_can_be_turned_off(api, monkeypatch, session_factory):
    monkeypatch.setattr(settings, "allow_self_registration", False)
    response = _signup(api)
    assert response.status_code == 403
    with session_factory() as db:
        assert db.execute(select(User).where(User.email == "new.person@example.com")).first() is None


def test_admin_user_creation_still_works_and_shares_the_duplicate_check(api):
    from conftest import login

    login(api, "admin@example.com")
    created = api.post(
        "/api/auth/users",
        json={"name": "Hunter Two", "email": "hunter2@example.com", "password": "pw-12345", "role": "Threat Hunter"},
    )
    assert created.status_code == 201
    assert created.json()["role"] == "Threat Hunter"
    again = api.post(
        "/api/auth/users",
        json={"name": "Hunter Two", "email": "HUNTER2@example.com", "password": "pw-12345", "role": "Viewer"},
    )
    assert again.status_code == 409
