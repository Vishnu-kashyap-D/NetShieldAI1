from __future__ import annotations

from fastapi import APIRouter

from app.config import settings
from app.detection_service import get_engine
from app.schemas import HealthOut

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    try:
        engine = get_engine()
        return HealthOut(
            status="ok",
            model_loaded=True,
            feature_count=len(engine.feature_names),
            artifacts_dir=str(settings.artifacts_dir),
        )
    except Exception as exc:  # model missing/incompatible -- report, don't crash the endpoint
        return HealthOut(
            status=f"degraded: {exc}",
            model_loaded=False,
            feature_count=None,
            artifacts_dir=str(settings.artifacts_dir),
        )
