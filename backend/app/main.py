from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import Base, engine
from app.detection_service import get_engine
from app.routers import alerts, chat, feedback, health, ingest, retrain, stats

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netshield.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    try:
        get_engine()
        logger.info("Detection engine loaded from %s", settings.artifacts_dir)
    except Exception:
        logger.exception(
            "Could not load the trained model from %s. /health will report degraded until "
            "artifacts/ has autoencoder.keras, bilstm_classifier.keras, and preprocessing.joblib.",
            settings.artifacts_dir,
        )
    yield


app = FastAPI(title="NetShield AI API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api")
app.include_router(ingest.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(chat.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(feedback.router, prefix="/api")
app.include_router(retrain.router, prefix="/api")
