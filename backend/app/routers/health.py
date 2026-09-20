from __future__ import annotations

import logging

from fastapi import APIRouter

from app.config import settings
from app.detection_service import get_engine
from app.schemas import HealthOut

logger = logging.getLogger("netshield.backend")

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    """Public on purpose (uptime checks), so it says only whether the model is up -- never where it lives or why
    it isn't: the filesystem path and the raw exception text go to the server log, not to anonymous callers."""
    try:
        engine = get_engine()
        return HealthOut(status="ok", model_loaded=True, feature_count=len(engine.feature_names))
    except Exception:  # model missing/incompatible -- report, don't crash the endpoint
        logger.exception("Health check: the detection model could not be loaded from %s.", settings.artifacts_dir)
        return HealthOut(
            status="degraded: the detection model is not loaded (details are in the server log)",
            model_loaded=False,
            feature_count=None,
        )
