from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import quote_plus

from pydantic_settings import BaseSettings, SettingsConfigDict

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

    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Explainability chatbot (backend/app/chat_service.py). Server-side only -- never sent to
    # the frontend. When unset, deterministic questions still work; open-ended questions get an
    # honest "AI explanation service unavailable" answer instead of a crash (see chat_service.py).
    anthropic_api_key: str | None = None
    chat_llm_model: str = "claude-opus-5"

    @property
    def sqlalchemy_url(self) -> str:
        # Credentials must be percent-encoded -- a literal "@" or ":" in the password
        # (e.g. "NetShield@2026") otherwise gets misparsed as the user@host separator.
        user = quote_plus(self.db_user)
        password = quote_plus(self.db_password)
        return f"mysql+pymysql://{user}:{password}@{self.db_host}:{self.db_port}/{self.db_name}?charset=utf8mb4"


settings = Settings()
