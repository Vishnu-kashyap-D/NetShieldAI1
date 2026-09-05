from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import threading
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import CAN_TRIGGER_RETRAIN, get_current_user, require_role
from app.config import settings
from app.database import SessionLocal, get_db
from app.detection_service import reload_engine
from app.models import TrainingRun, User
from app.schemas import RetrainTriggerIn, TrainingRunOut

# GET requires only a valid session (any role can see training history); POST additionally
# requires CAN_TRIGGER_RETRAIN, enforced per-route below since it's stricter than the router default.
router = APIRouter(prefix="/retrain", tags=["retrain"], dependencies=[Depends(get_current_user)])


def _count_feedback_rows(path: Path) -> int | None:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as handle:
        return max(sum(1 for _ in handle) - 1, 0)  # minus header


def _run_training(run_id: int) -> None:
    """Runs cyber_ai.train as a subprocess and updates the TrainingRun row on completion.

    Retraining takes minutes, so this runs on a background thread instead of blocking
    the request; a full task queue (Celery etc.) would be overkill for this project's scope.
    """
    db = SessionLocal()
    try:
        run = db.get(TrainingRun, run_id)
        settings.training_logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = settings.training_logs_dir / f"run_{run_id}.log"

        command = [
            sys.executable, "-m", "cyber_ai.train",
            "--config", str(settings.train_config),
            "--feedback-csv", str(settings.feedback_store),
            "--artifacts-dir", str(settings.artifacts_dir),
            "--reports-dir", str(settings.reports_dir),
        ]
        with log_path.open("w", encoding="utf-8") as log_file:
            result = subprocess.run(
                command, cwd=str(settings.artifacts_dir.parent), stdout=log_file,
                stderr=subprocess.STDOUT, check=False,
            )

        run.log_path = str(log_path)
        run.finished_at = dt.datetime.utcnow()
        if result.returncode == 0:
            run.status = "completed"
            metrics_path = settings.reports_dir / "training_metrics.json"
            if metrics_path.exists():
                run.metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            reload_engine()  # next request picks up the freshly retrained weights
        else:
            run.status = "failed"
            run.error = f"cyber_ai.train exited with code {result.returncode}; see {log_path}"
        db.commit()
    except Exception as exc:  # keep the background thread from dying silently
        run = db.get(TrainingRun, run_id)
        if run is not None:
            run.status = "failed"
            run.error = str(exc)
            run.finished_at = dt.datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.post("", response_model=TrainingRunOut)
def trigger_retrain(
    payload: RetrainTriggerIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(*CAN_TRIGGER_RETRAIN)),
) -> TrainingRunOut:
    already_running = db.execute(select(TrainingRun).where(TrainingRun.status == "running")).scalars().first()
    if already_running is not None:
        raise HTTPException(status_code=409, detail=f"Training run {already_running.id} is already running.")

    # `triggered_by` is the authenticated user's own name, never the client-supplied
    # `payload.triggered_by` -- a client shouldn't be able to attribute a training run to
    # someone else. RetrainTriggerIn.triggered_by is kept only so old callers don't 422.
    run = TrainingRun(
        status="running",
        triggered_by=user.name,
        feedback_rows_used=_count_feedback_rows(settings.feedback_store),
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    thread = threading.Thread(target=_run_training, args=(run.id,), daemon=True)
    thread.start()

    return TrainingRunOut.model_validate(run)


@router.get("", response_model=list[TrainingRunOut])
def list_runs(db: Session = Depends(get_db)) -> list[TrainingRunOut]:
    rows = db.execute(select(TrainingRun).order_by(TrainingRun.started_at.desc())).scalars().all()
    return [TrainingRunOut.model_validate(row) for row in rows]


@router.get("/{run_id}", response_model=TrainingRunOut)
def get_run(run_id: int, db: Session = Depends(get_db)) -> TrainingRunOut:
    run = db.get(TrainingRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Training run not found")
    return TrainingRunOut.model_validate(run)
