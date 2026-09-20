from __future__ import annotations

import csv
import datetime as dt
import io
import os
import re
import threading
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cyber_ai.feedback import feedback_label

from app.auth import CAN_SUBMIT_FEEDBACK, get_current_user, require_role
from app.config import settings
from app.database import get_db
from app.detection_service import get_engine
from app.models import Alert, Feedback, User
from app.schemas import FeedbackIn, FeedbackOut

# GET requires only a valid session (any role can review feedback history); POST additionally
# requires CAN_SUBMIT_FEEDBACK, enforced per-route below since it's stricter than the router default.
router = APIRouter(prefix="/feedback", tags=["feedback"], dependencies=[Depends(get_current_user)])

# submit_feedback is a sync `def`, so FastAPI runs concurrent calls to it in real OS threads
# (Starlette's thread pool). The whole look-up-then-write sequence below runs under this one
# process-wide lock, so two analysts submitting at the same moment can't both see "no feedback yet"
# / "no header yet" and double-write. It's exactly sufficient for one process; the UNIQUE
# constraint on feedback.alert_id is what arbitrates between processes for the database, but the
# CSV file itself has no cross-process lock -- a multi-worker deployment needs real file locking
# (or a single writer) for it. See "Running with multiple workers" in backend/README.md.
_feedback_write_lock = threading.Lock()


def _row_line(feature_names: list[str], features: dict, label: str) -> str:
    """The exact CSV line (no terminator) _append_to_feedback_store writes for this alert + label."""
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="").writerow([features.get(name, "") for name in feature_names] + [label])
    return buffer.getvalue()


def _append_to_feedback_store(store_path: Path, feature_names: list[str], features: dict, label: str) -> None:
    store_path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not store_path.exists()
    with store_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*feature_names, "Label"])
        if is_new:
            writer.writeheader()
        row = {name: features.get(name, "") for name in feature_names}
        row["Label"] = label
        writer.writerow(row)


def _replace_in_feedback_store(
    store_path: Path, feature_names: list[str], features: dict, old_label: str, new_label: str
) -> None:
    """Swap this alert's earlier training row for one carrying its corrected label.

    Rows in the store carry no alert id (its columns are exactly what cyber_ai.train reads -- an
    extra column would be mistaken for a feature), so the earlier row is found by content: it is
    the line _append_to_feedback_store would have produced for this alert's feature vector and
    the old label. A resubmission used to *append*, leaving the stale label in the file as a
    second, contradictory training row for the same traffic.
    """
    old_line = _row_line(feature_names, features, old_label)
    if store_path.exists():
        # newline="" keeps the file's own line endings byte-for-byte (the csv module writes \r\n),
        # and splitting only on \n means an odd character inside an analyst-typed label (which
        # str.splitlines would treat as a line break) can't shift the match.
        with store_path.open("r", encoding="utf-8", newline="") as handle:
            lines = re.findall(r"[^\n]*\n|[^\n]+", handle.read())
        for index, line in enumerate(lines):
            if line.rstrip("\r\n") == old_line:
                del lines[index]
                # Temp file + atomic replace, so a crash mid-rewrite can't truncate the store.
                tmp = store_path.with_name(store_path.name + ".tmp")
                tmp.write_text("".join(lines), encoding="utf-8", newline="")
                os.replace(tmp, store_path)
                break
    _append_to_feedback_store(store_path, feature_names, features, new_label)


@router.post("", response_model=FeedbackOut)
def submit_feedback(
    payload: FeedbackIn,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(*CAN_SUBMIT_FEEDBACK)),
) -> FeedbackOut:
    alert = db.get(Alert, payload.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    label = feedback_label(payload.validated_label)
    engine = get_engine()

    # The stored vector becomes a retraining row laid out under the *currently deployed* feature
    # set (missing names would be written as blanks and silently imputed). An alert scored under a
    # different feature set can't honestly be used that way -- say so instead.
    if alert.feature_schema_version not in (None, engine.feature_schema_version):
        raise HTTPException(
            status_code=409,
            detail=(
                f"This alert was scored under feature set {alert.feature_schema_version}, but the deployed "
                f"model uses {engine.feature_schema_version}; its stored features can't be used as a "
                "training row. Re-ingest the traffic to get a current alert, then give feedback on that."
            ),
        )

    with _feedback_write_lock:
        existing = db.execute(select(Feedback).where(Feedback.alert_id == alert.id)).scalar_one_or_none()

        if existing is None:
            # Database first: the unique constraint decides who wins a race, and only the winner
            # then writes the CSV row (the reverse order could leave an orphan training row).
            feedback = Feedback(
                alert_id=alert.id,
                validated_label=label,
                analyst=payload.analyst,
                notes=payload.notes,
                written_to_feedback_store=False,
            )
            db.add(feedback)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                raise HTTPException(
                    status_code=409,
                    detail="Feedback for this alert was just submitted elsewhere; resubmit to update it.",
                ) from None
            _append_to_feedback_store(settings.feedback_store, engine.feature_names, alert.features, label)
        else:
            feedback = existing
            if not existing.written_to_feedback_store:
                # An earlier attempt saved the row but failed before writing the CSV: finish the job.
                _append_to_feedback_store(settings.feedback_store, engine.feature_names, alert.features, label)
            elif existing.validated_label != label:
                # CSV first (it needs the *old* label to find the row to replace); if the DB commit
                # below then fails, a retry just re-appends an identical line, which training's
                # exact-duplicate removal drops.
                _replace_in_feedback_store(
                    settings.feedback_store, engine.feature_names, alert.features, existing.validated_label, label
                )
            # Same label resubmitted: nothing to change in the CSV -- resubmitting is idempotent.
            feedback.validated_label = label
            feedback.analyst = payload.analyst
            feedback.notes = payload.notes
            feedback.created_at = dt.datetime.utcnow()  # time of the current validated label

        feedback.written_to_feedback_store = True
        db.commit()
        db.refresh(feedback)
    return FeedbackOut.model_validate(feedback)


@router.get("", response_model=list[FeedbackOut])
def list_feedback(db: Session = Depends(get_db)) -> list[FeedbackOut]:
    rows = db.execute(select(Feedback).order_by(Feedback.created_at.desc())).scalars().all()
    return [FeedbackOut.model_validate(row) for row in rows]
