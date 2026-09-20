from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

# Make `import app...` work no matter which directory pytest is launched from.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bcrypt
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_model: loads the committed artifacts/ and scores the demo CSV (~30s); deselect with -m 'not real_model'"
    )


FEATURES = ["Flow Duration", "Total Fwd Packets", "Flow Bytes/s"]


@pytest.fixture(autouse=True)
def _fresh_rate_limits():
    """The login/chat limiters are module-level, in-memory state -- without this, failed logins in one
    test would lock out the next test's (same "testclient" address) login."""
    from app.routers import auth as auth_router, chat as chat_router

    for limiter in (auth_router._login_account_limiter, auth_router._login_ip_limiter, chat_router._chat_limiter):
        limiter._events.clear()
    yield


@pytest.fixture()
def sqlite_engine():
    """A throwaway in-memory database with the app's real tables (not the developer's MySQL)."""
    from app.database import Base
    import app.models  # noqa: F401  (registers the tables on Base.metadata)

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def session_factory(sqlite_engine):
    return sessionmaker(bind=sqlite_engine, autoflush=False, autocommit=False)


@pytest.fixture()
def api(session_factory, tmp_path, monkeypatch):
    """The real FastAPI app wired to the in-memory DB, a temp feedback CSV and a stub model.

    Importing app.main loads TensorFlow (a few seconds) but no model is constructed: the feedback
    route's get_engine is replaced with a stub, and the TestClient is used without its lifespan,
    so nothing touches MySQL or artifacts/.
    """
    from fastapi.testclient import TestClient

    from app.auth import Role, hash_password
    from app.config import settings
    from app.database import get_db
    from app.feature_schema import feature_schema_version
    from app.main import app
    from app.models import User
    from app.routers import feedback as feedback_router

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    # bcrypt at production cost (12 rounds) is ~0.25s per hash/verify -- minutes across a suite that
    # signs in hundreds of times. Rounds are stored inside each hash, so verification still works.
    real_gensalt = bcrypt.gensalt
    monkeypatch.setattr(bcrypt, "gensalt", lambda rounds=4, prefix=b"2b": real_gensalt(rounds=4, prefix=prefix))
    monkeypatch.setattr(settings, "feedback_store", tmp_path / "validated_traffic.csv")
    engine_stub = SimpleNamespace(feature_names=FEATURES, feature_schema_version=feature_schema_version(FEATURES))
    monkeypatch.setattr(feedback_router, "get_engine", lambda: engine_stub)

    with session_factory() as db:
        for email, role in [
            ("analyst@example.com", Role.SECURITY_ANALYST),
            ("viewer@example.com", Role.VIEWER),
            ("hunter@example.com", Role.THREAT_HUNTER),
            ("admin@example.com", Role.ADMINISTRATOR),
        ]:
            db.add(User(name=email.split("@")[0], email=email, password_hash=hash_password("pw-12345"), role=role))
        db.commit()

    client = TestClient(app)
    client.engine_stub = engine_stub
    client.feedback_csv = tmp_path / "validated_traffic.csv"
    yield client
    app.dependency_overrides.clear()


def login(client, email: str) -> None:
    response = client.post("/api/auth/login", json={"email": email, "password": "pw-12345"})
    assert response.status_code == 200, response.text


def make_alert(session_factory, features: dict | None = None, schema_version: str | None = "auto") -> int:
    """Insert one alert and return its id. `schema_version="auto"` versions it like the real engine would."""
    from app.feature_schema import feature_schema_version
    from app.models import Alert

    features = features if features is not None else {name: float(i + 1) for i, name in enumerate(FEATURES)}
    if schema_version == "auto":
        schema_version = feature_schema_version(features.keys())
    with session_factory() as db:
        alert = Alert(
            batch_id="b" * 36, window_start=0, window_end=9, source_file="t.csv", actual_label=None,
            actual_category="Normal", predicted_label="DoS / DDoS", confidence=0.99, anomaly_score=1.5,
            anomaly_threshold=0.8, is_anomaly=True, pipeline_action="Classified and alerted", risk_score=0.99,
            risk_level="High", top_classifier_features=None, top_anomaly_features=None, features=features,
            feature_schema_version=schema_version,
        )
        db.add(alert)
        db.commit()
        return alert.id
