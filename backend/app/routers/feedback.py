from __future__ import annotations

import csv
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
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
    _append_to_feedback_store(settings.feedback_store, engine.feature_names, alert.features, label)

    feedback = Feedback(
        alert_id=alert.id,
        validated_label=label,
        analyst=payload.analyst,
        notes=payload.notes,
        written_to_feedback_store=True,
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    return FeedbackOut.model_validate(feedback)


@router.get("", response_model=list[FeedbackOut])
def list_feedback(db: Session = Depends(get_db)) -> list[FeedbackOut]:
    rows = db.execute(select(Feedback).order_by(Feedback.created_at.desc())).scalars().all()
    return [FeedbackOut.model_validate(row) for row in rows]
