from __future__ import annotations

import datetime as dt
import json
import shutil
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

# The two headline metrics a retrain could plausibly regress on. A small tolerance avoids
# rejecting a run over noise-level float differences between two otherwise-equivalent runs.
_QUALITY_GATE_TOLERANCE = 0.01


def _count_feedback_rows(path: Path) -> int | None:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as handle:
        return max(sum(1 for _ in handle) - 1, 0)  # minus header


def _headline_metrics(metrics: dict) -> tuple[float, float] | None:
    try:
        bilstm_accuracy = metrics["bilstm_classifier"]["classification_report"]["accuracy"]
        ae_balanced_accuracy = metrics["autoencoder"]["threshold_report"]["balanced_accuracy"]
        return float(bilstm_accuracy), float(ae_balanced_accuracy)
    except (KeyError, TypeError, ValueError):
        return None


def _should_deploy(new_metrics: dict, baseline_metrics: dict) -> tuple[bool, str]:
    """Compares a freshly-trained model's headline metrics against the currently-deployed
    model's. Never lets a strictly worse model silently replace a better one -- see the
    quality-gate note in _run_training for why this exists."""
    new_headline = _headline_metrics(new_metrics)
    baseline_headline = _headline_metrics(baseline_metrics)
    if new_headline is None or baseline_headline is None:
        return True, "Could not compare metrics (unexpected shape); deployed by default."

    new_bilstm, new_ae = new_headline
    base_bilstm, base_ae = baseline_headline

    if new_bilstm < base_bilstm - _QUALITY_GATE_TOLERANCE:
        return False, f"BiLSTM accuracy regressed: {new_bilstm:.4f} vs currently-deployed {base_bilstm:.4f}."
    if new_ae < base_ae - _QUALITY_GATE_TOLERANCE:
        return False, f"Autoencoder balanced accuracy regressed: {new_ae:.4f} vs currently-deployed {base_ae:.4f}."
    return True, (
        f"BiLSTM accuracy {new_bilstm:.4f} (was {base_bilstm:.4f}), "
        f"Autoencoder balanced accuracy {new_ae:.4f} (was {base_ae:.4f})."
    )


def _run_training(run_id: int) -> None:
    """Runs cyber_ai.train as a subprocess and updates the TrainingRun row on completion.

    Retraining takes minutes, so this runs on a background thread instead of blocking
    the request; a full task queue (Celery etc.) would be overkill for this project's scope.

    Quality gate: cyber_ai.train writes its output directly into artifacts_dir, overwriting
    the live model's files in place. A successful *run* (exit code 0) is not the same thing
    as a *better* model -- a small/skewed feedback batch could train a genuinely worse one.
    Before running, the current (known-good) artifacts are backed up; a successful run only
    gets deployed (reload_engine() called) if its headline metrics aren't worse than the
    currently-deployed model's. If they are, the backup is restored over the regressed files
    so the worse weights don't even survive on disk for a later process restart to pick up,
    and the run is marked "rejected" rather than "failed" (training itself worked; it just
    didn't clear the bar to go live -- the reason is recorded in run.error either way).
    "rejected" (not the more descriptive "completed_not_deployed") because TrainingRun.status
    is a fixed-width String(16) column and there's no migration tooling in this project to
    widen an existing MySQL column -- see the DB/infra audit's Phase 4 item on Alembic.
    """
    db = SessionLocal()
    artifacts_backup = settings.artifacts_dir.parent / "artifacts_backup_before_retrain"
    try:
        run = db.get(TrainingRun, run_id)
        settings.training_logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = settings.training_logs_dir / f"run_{run_id}.log"

        if artifacts_backup.exists():
            shutil.rmtree(artifacts_backup)
        if settings.artifacts_dir.exists():
            shutil.copytree(settings.artifacts_dir, artifacts_backup)

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

        if result.returncode != 0:
            run.status = "failed"
            run.error = f"cyber_ai.train exited with code {result.returncode}; see {log_path}"
            db.commit()
            return

        metrics_path = settings.reports_dir / "training_metrics.json"
        new_metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else None
        run.metrics = new_metrics

        if new_metrics is None:
            run.status = "failed"
            run.error = "Training reported success but produced no training_metrics.json."
            db.commit()
            return

        baseline_run = db.execute(
            select(TrainingRun)
            .where(TrainingRun.status == "completed", TrainingRun.id != run_id)
            .order_by(TrainingRun.finished_at.desc())
        ).scalars().first()

        if baseline_run is None or baseline_run.metrics is None:
            # Nothing deployed yet to compare against -- first successful run always deploys.
            run.status = "completed"
            reload_engine()
        else:
            should_deploy, reason = _should_deploy(new_metrics, baseline_run.metrics)
            if should_deploy:
                run.status = "completed"
                reload_engine()
            else:
                run.status = "rejected"
                run.error = f"New model not deployed (quality gate): {reason}"
                if artifacts_backup.exists():
                    if settings.artifacts_dir.exists():
                        shutil.rmtree(settings.artifacts_dir)
                    shutil.copytree(artifacts_backup, settings.artifacts_dir)
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
