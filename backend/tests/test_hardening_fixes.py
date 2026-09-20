"""Four small hardening fixes from the threat model: health disclosure, feedback authorship, login timing,
and the ingest route blocking the event loop."""
from __future__ import annotations

import asyncio
import inspect
import time

import httpx
import pytest

from conftest import login, make_alert
from stub_engine import known_traffic_csv, make_engine

# --- /api/health does not describe the server to anonymous callers ---------------------------------------


class TestHealthDisclosure:
    def test_a_healthy_response_says_nothing_about_the_filesystem(self, api, monkeypatch):
        from app.routers import health as health_router

        monkeypatch.setattr(health_router, "get_engine", make_engine)
        body = api.get("/api/health").json()
        assert body == {"status": "ok", "model_loaded": True, "feature_count": 3}
        assert "artifacts" not in api.get("/api/health").text.lower()

    def test_a_failure_keeps_the_path_and_the_exception_out_of_the_response(self, api, monkeypatch, caplog):
        from app.routers import health as health_router

        def boom():
            raise RuntimeError("cannot load /srv/secret/place/preprocessing.joblib: 'SimpleImputer' has no _fill_dtype")

        monkeypatch.setattr(health_router, "get_engine", boom)
        with caplog.at_level("ERROR", logger="netshield.backend"):
            response = api.get("/api/health")
        # decoded values, not the raw JSON text: on Windows a path's backslashes are escaped there and would never match
        body = " ".join(str(value) for value in response.json().values())
        assert response.status_code == 200 and response.json()["model_loaded"] is False
        assert response.json()["status"].startswith("degraded")
        from app.config import settings

        for leaked in ("/srv/secret", "preprocessing.joblib", "SimpleImputer", "RuntimeError", str(settings.artifacts_dir)):
            assert leaked not in body
        # ...but the operator still gets the whole story, in the log
        assert "/srv/secret/place/preprocessing.joblib" in caplog.text or any("SimpleImputer" in str(r.exc_info) for r in caplog.records)

    def test_the_route_stays_public(self, api, monkeypatch):
        from app.routers import health as health_router

        monkeypatch.setattr(health_router, "get_engine", make_engine)
        assert api.get("/api/health").status_code == 200


# --- feedback records the signed-in user, not whoever the client says ------------------------------------


class TestFeedbackAuthorship:
    def submit(self, api, alert_id, label="Normal", **extra):
        return api.post("/api/feedback", json={"alert_id": alert_id, "validated_label": label, **extra})

    def test_a_client_supplied_analyst_name_is_ignored(self, api, session_factory):
        alert_id = make_alert(session_factory)
        login(api, "analyst@example.com")
        response = self.submit(api, alert_id, analyst="Ava Administrator")            # try to blame somebody else
        assert response.status_code == 200 and response.json()["analyst"] == "analyst"

    def test_omitting_the_name_still_records_who_did_it(self, api, session_factory):
        alert_id = make_alert(session_factory)
        login(api, "hunter@example.com")
        assert self.submit(api, alert_id).json()["analyst"] == "hunter"

    def test_the_list_shows_the_real_author(self, api, session_factory):
        alert_id = make_alert(session_factory)
        login(api, "analyst@example.com")
        self.submit(api, alert_id, analyst="Somebody Else")
        assert [row["analyst"] for row in api.get("/api/feedback").json()] == ["analyst"]

    def test_a_correction_by_someone_else_is_attributed_to_them(self, api, session_factory):
        alert_id = make_alert(session_factory)
        login(api, "analyst@example.com")
        self.submit(api, alert_id, label="Normal")
        api.cookies.clear()
        login(api, "admin@example.com")
        response = self.submit(api, alert_id, label="DoS / DDoS", analyst="analyst")   # and cannot pass it off as theirs
        assert response.json()["analyst"] == "admin"
        assert [row["analyst"] for row in api.get("/api/feedback").json()] == ["admin"]


# --- an unknown email costs as much time as a wrong password ---------------------------------------------


class TestLoginTiming:
    @pytest.fixture()
    def checks(self, monkeypatch):
        """Records every password check the login route performs."""
        from app.routers import auth as auth_router

        calls = []
        real = auth_router.verify_password

        def spy(plain, hashed):
            calls.append(hashed)
            return real(plain, hashed)

        monkeypatch.setattr(auth_router, "verify_password", spy)
        return calls

    def attempt(self, api, email, password):
        return api.post("/api/auth/login", json={"email": email, "password": password})

    def test_a_wrong_password_and_an_unknown_email_each_run_exactly_one_password_check(self, api, checks):
        assert self.attempt(api, "analyst@example.com", "wrong").status_code == 401
        assert len(checks) == 1
        assert self.attempt(api, "nobody@example.com", "wrong").status_code == 401
        assert len(checks) == 2                                    # not skipped: this is what used to be instant

    def test_the_unknown_email_is_checked_against_a_real_bcrypt_hash(self, api, checks):
        from app.routers.auth import _timing_decoy_hash

        self.attempt(api, "nobody@example.com", "x")
        assert checks == [_timing_decoy_hash()]
        assert _timing_decoy_hash().startswith("$2")               # a genuine bcrypt hash, so the check is genuinely slow
        assert _timing_decoy_hash() is _timing_decoy_hash()        # made once, not on every attempt

    def test_the_decoy_can_never_authenticate_anyone(self, api, checks):
        """Even guessing the decoy's own password must not log in an email that has no account."""
        response = self.attempt(api, "nobody@example.com", "this-account-does-not-exist")
        assert response.status_code == 401 and "set-cookie" not in response.headers

    def test_a_correct_login_still_runs_one_check_and_works(self, api, checks):
        assert self.attempt(api, "analyst@example.com", "pw-12345").status_code == 200
        assert len(checks) == 1

    def test_both_failures_look_identical_to_the_caller(self, api):
        first = self.attempt(api, "analyst@example.com", "wrong")
        second = self.attempt(api, "nobody@example.com", "wrong")
        assert (first.status_code, first.json()) == (second.status_code, second.json())

    def test_unknown_emails_are_throttled_exactly_like_known_ones(self, api):
        from app.config import settings

        for _ in range(settings.login_max_failures):
            assert self.attempt(api, "nobody@example.com", "wrong").status_code == 401
        assert self.attempt(api, "nobody@example.com", "wrong").status_code == 429


# --- scoring an upload must not freeze the rest of the API ------------------------------------------------


class TestIngestDoesNotBlockTheServer:
    def test_the_route_is_a_plain_function_so_fastapi_runs_it_on_a_worker_thread(self):
        from app.routers import ingest

        assert not inspect.iscoroutinefunction(ingest.ingest_csv)

    def test_other_requests_are_served_while_a_slow_upload_is_being_scored(self, api, monkeypatch):
        """Regression: ingest was `async def` and scored inside the handler, so one big upload stalled every request
        (health checks, logins, the dashboard) for its whole duration. Here scoring takes a full second; an unrelated
        request made while it runs must not have to wait for it."""
        from app.main import app
        from app.routers import ingest as ingest_router

        slow_engine = make_engine()
        real_score = slow_engine.score_dataframe

        def slow_score(*args, **kwargs):
            time.sleep(1.0)                                         # genuinely blocking, like real model inference
            return real_score(*args, **kwargs)

        slow_engine.score_dataframe = slow_score
        monkeypatch.setattr(ingest_router, "get_engine", lambda: slow_engine)

        async def scenario():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                assert (await client.post("/api/auth/login", json={"email": "hunter@example.com", "password": "pw-12345"})).status_code == 200
                upload = asyncio.create_task(
                    client.post("/api/ingest/csv", files={"file": ("k.csv", known_traffic_csv(), "text/csv")})
                )
                await asyncio.sleep(0.3)                            # the upload is now inside the slow scoring call
                started = time.perf_counter()
                other = await client.get("/api/auth/roles")
                waited = time.perf_counter() - started
                finished = await upload
                return waited, other.status_code, finished.status_code

        waited, other_status, upload_status = asyncio.run(scenario())
        assert (other_status, upload_status) == (200, 200)
        assert waited < 0.5, f"an unrelated request waited {waited:.2f}s behind the upload -- the event loop is blocked"
