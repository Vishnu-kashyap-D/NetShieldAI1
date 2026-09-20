from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import quote_plus

from pydantic_settings import BaseSettings, SettingsConfigDict

# Must happen before the first `import tensorflow` anywhere in the process. app.main imports
# this module first, then app.detection_service (which imports tensorflow before it imports
# cyber_ai) -- so cyber_ai/__init__.py's own copy of this line runs too late for the backend.
# See cyber_ai/__init__.py for the full explanation of why this is needed.
os.environ.setdefault("TF_USE_LEGACY_KERAS", "1")

REPO_ROOT = Path(__file__).resolve().parents[2]

# cyber_ai lives at the repo root, one level above backend/. Running uvicorn from
# either the repo root or backend/ (both are common) shouldn't change whether it's
# importable, so make sure the repo root is always on sys.path.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(REPO_ROOT / "backend" / ".env"), extra="ignore")

    db_host: str = "localhost"
    db_port: int = 3306
    db_user: str = "root"
    db_password: str = ""
    db_name: str = "netshield"

    artifacts_dir: Path = REPO_ROOT / "artifacts"
    reports_dir: Path = REPO_ROOT / "reports"
    data_dir: Path = REPO_ROOT / "MachineLearningCVE"
    demo_csv: Path = REPO_ROOT / "demo" / "panel_demo_traffic.csv"
    feedback_store: Path = REPO_ROOT / "data" / "feedback" / "validated_traffic.csv"
    train_config: Path = REPO_ROOT / "configs" / "default.yaml"
    training_logs_dir: Path = REPO_ROOT / "reports" / "training_runs"

    # Shared "reload the model" signal between worker processes (see app/engine_cache.py). Kept
    # OUTSIDE artifacts_dir on purpose: the retrain quality gate deletes and restores that whole
    # directory when it rejects a run.
    model_generation_file: Path = REPO_ROOT / ".model_generation"

    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Guards POST /api/ingest/csv against an accidental multi-GB upload being buffered whole
    # into memory (the endpoint reads the full body before parsing). 200MB comfortably covers
    # a real CICIDS2017-sized CSV with room to spare.
    max_upload_bytes: int = 200 * 1024 * 1024

    # Both chatbots (backend/app/chat_service.py -- the per-alert assistant's LLM fallback AND the
    # sidebar's general "Assistant" project/threat chatbot) run on this one Gemini key/model, so the
    # whole app needs only one LLM key configured, not two. When unset: the per-alert assistant's
    # deterministic questions still work fully; open-ended questions on either assistant get an
    # honest "unavailable" answer instead of a crash (see chat_service.py).
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.6-flash"

    # Authentication (backend/app/auth.py). Sessions are opaque random tokens stored in the
    # `sessions` table, not JWTs -- no signing secret to manage, and revoking a session (logout)
    # is a real DB delete rather than waiting out a token's expiry.
    session_cookie_name: str = "netshield_session"
    session_ttl_hours: int = 24 * 7
    # False on purpose for local development: this app runs over plain http://localhost, and a
    # `Secure` cookie is silently dropped by the browser on a non-https origin, which would make
    # login look like it "does nothing." MUST be set to true (SESSION_COOKIE_SECURE=true) the
    # moment this is served over real HTTPS, or the session cookie can leak over plain http.
    session_cookie_secure: bool = False

    # Abuse limits (backend/app/ratelimit.py -- in-memory, so per worker process). Failed logins
    # are counted per (client IP, email) AND per client IP across all emails, so one attacker
    # can't lock a real user out from another address, and can't dodge the per-account limit by
    # spraying many emails either. The client IP is the direct socket peer -- X-Forwarded-For is
    # deliberately not trusted, since any client can forge it.
    login_max_failures: int = 5
    login_ip_max_failures: int = 20
    login_window_seconds: int = 300
    # Requests per minute per signed-in user, shared across both chatbots (each may call a paid LLM).
    chat_max_requests_per_minute: int = 20

    @property
    def sqlalchemy_url(self) -> str:
        # Credentials must be percent-encoded -- a literal "@" or ":" in the password
        # (e.g. "NetShield@2026") otherwise gets misparsed as the user@host separator.
        user = quote_plus(self.db_user)
        password = quote_plus(self.db_password)
        return f"mysql+pymysql://{user}:{password}@{self.db_host}:{self.db_port}/{self.db_name}?charset=utf8mb4"


settings = Settings()
