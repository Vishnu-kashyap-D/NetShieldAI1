"""5.1 -- the API's own hardening: CSRF Origin verification, security headers, rate limiter, config parsing."""
from __future__ import annotations

import pytest

from conftest import login
from app.config import settings

ALLOWED_ORIGIN = settings.cors_origins[0]  # whatever the dashboard origin is configured as (default http://localhost:3000)
EVIL_ORIGIN = "http://localhost:5500"  # same *site* as the dashboard (ports are ignored by SameSite) but not an allowed origin


# --- CSRF: Origin verification ---------------------------------------------------------------------


def _logout(client, **headers):
    return client.post("/api/auth/logout", headers=headers)


def test_a_state_changing_request_from_a_foreign_origin_is_blocked(api):
    login(api, "viewer@example.com")
    response = _logout(api, Origin=EVIL_ORIGIN)
    assert response.status_code == 403 and "cross-origin" in response.json()["detail"].lower()
    assert api.get("/api/auth/me").status_code == 200  # ...and the session was NOT logged out by it


def test_the_same_request_from_the_dashboard_origin_goes_through(api):
    login(api, "viewer@example.com")
    assert _logout(api, Origin=ALLOWED_ORIGIN).status_code == 200


def test_a_request_with_no_origin_or_referer_is_not_a_browser_cross_site_request(api):
    """curl, the stream simulator and other scripts send neither header."""
    login(api, "viewer@example.com")
    assert _logout(api).status_code == 200


@pytest.mark.parametrize("origin", ["null", "https://evil.example", f"{ALLOWED_ORIGIN}.evil.example", ""])
def test_hostile_or_malformed_origins_are_blocked(api, origin):
    login(api, "viewer@example.com")
    assert _logout(api, Origin=origin).status_code == 403


def test_the_referer_is_checked_when_there_is_no_origin(api):
    login(api, "viewer@example.com")
    assert _logout(api, Referer=f"{EVIL_ORIGIN}/attack.html").status_code == 403
    assert _logout(api, Referer=f"{ALLOWED_ORIGIN}/alerts").status_code == 200


def test_the_servers_own_origin_is_allowed_so_the_swagger_ui_still_works(api):
    login(api, "viewer@example.com")
    assert _logout(api, Origin="http://testserver").status_code == 200


def test_safe_methods_are_never_origin_checked(api):
    login(api, "viewer@example.com")
    assert api.get("/api/auth/me", headers={"Origin": EVIL_ORIGIN}).status_code == 200


def test_the_login_post_itself_is_protected_too(api):
    response = api.post(
        "/api/auth/login", json={"email": "viewer@example.com", "password": "pw-12345"}, headers={"Origin": EVIL_ORIGIN}
    )
    assert response.status_code == 403 and "set-cookie" not in response.headers


def test_the_cors_preflight_from_the_dashboard_is_answered(api):
    response = api.options(
        "/api/auth/login",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"


def test_a_foreign_origin_gets_no_cors_permission(api):
    response = api.get("/api/auth/roles", headers={"Origin": EVIL_ORIGIN})
    assert "access-control-allow-origin" not in response.headers


# --- security headers ------------------------------------------------------------------------------


def test_api_responses_carry_the_hardening_headers(api):
    response = api.get("/api/auth/me")  # even an error response
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert response.headers["cache-control"] == "no-store"
    assert "strict-transport-security" not in response.headers  # plain http: HSTS would be noise


def test_hsts_is_sent_only_over_https(api):
    from fastapi.testclient import TestClient

    from app.main import app

    https = TestClient(app, base_url="https://testserver")
    assert "max-age=" in https.get("/api/auth/me").headers["strict-transport-security"]


def test_the_docs_page_is_not_given_the_api_csp(api):
    """/docs loads its JS/CSS from a CDN; a blanket default-src 'none' would break it."""
    response = api.get("/docs")
    assert response.status_code == 200
    assert "content-security-policy" not in response.headers
    assert response.headers["x-frame-options"] == "DENY"


# --- rate limiter ----------------------------------------------------------------------------------


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture()
def clock(monkeypatch):
    import app.ratelimit as ratelimit

    fake = _Clock()
    monkeypatch.setattr(ratelimit.time, "monotonic", fake)
    return fake


def test_the_limiter_blocks_at_the_limit_and_reports_when_to_retry(clock):
    from app.ratelimit import SlidingWindowLimiter

    limiter = SlidingWindowLimiter(max_events=2, window_seconds=60)
    limiter.record("k"); clock.now += 10
    limiter.record("k"); clock.now += 10
    assert limiter.retry_after("k") == pytest.approx(40)  # the oldest event leaves the window in 40s
    clock.now += 40
    assert limiter.retry_after("k") == 0.0                # ...and then one slot is free again


def test_keys_are_independent(clock):
    from app.ratelimit import SlidingWindowLimiter

    limiter = SlidingWindowLimiter(1, 60)
    limiter.record("a")
    assert limiter.retry_after("a") > 0 and limiter.retry_after("b") == 0


def test_acquire_admits_up_to_the_limit_and_a_refusal_records_nothing(clock):
    from app.ratelimit import SlidingWindowLimiter

    limiter = SlidingWindowLimiter(2, 60)
    assert limiter.acquire("u") == 0 and limiter.acquire("u") == 0
    assert limiter.acquire("u") > 0
    assert len(limiter._events["u"]) == 2       # the refused call did not extend the block
    clock.now += 61
    assert limiter.acquire("u") == 0


def test_clear_forgets_a_key(clock):
    from app.ratelimit import SlidingWindowLimiter

    limiter = SlidingWindowLimiter(1, 60)
    limiter.record("k")
    limiter.clear("k")
    assert limiter.retry_after("k") == 0


def test_the_number_of_tracked_keys_is_bounded(clock):
    """A login spray across random emails must not grow memory without limit."""
    from app.ratelimit import SlidingWindowLimiter

    limiter = SlidingWindowLimiter(5, 60)
    limiter._MAX_KEYS = 100
    for n in range(100):
        limiter.record(f"k{n}")
    clock.now += 61  # all of them have now expired, so the next new key triggers a sweep
    limiter.record("fresh")
    assert len(limiter._events) == 1


# --- configuration ---------------------------------------------------------------------------------


def test_cors_origins_parse_as_a_json_list(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("CORS_ORIGINS", '["https://dash.example.com", "http://localhost:3000"]')
    assert Settings().cors_origins == ["https://dash.example.com", "http://localhost:3000"]


def test_a_comma_separated_cors_origins_value_fails_loudly_instead_of_silently(monkeypatch):
    """Documented in backend/.env.example: the comma form is NOT accepted."""
    from app.config import Settings

    monkeypatch.setenv("CORS_ORIGINS", "https://a.example,https://b.example")
    with pytest.raises(Exception):
        Settings()
