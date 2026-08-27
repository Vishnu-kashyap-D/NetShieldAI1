from __future__ import annotations

import csv
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.detection_service import get_engine
from app.models import Alert, Feedback
from app.schemas import FeedbackIn, FeedbackOut

router = APIRouter(prefix="/feedback", tags=["feedback"])

# Mirrors cyber_ai.feedback._feedback_label: an analyst confirming "this alert was a
# false positive" should feed back as BENIGN, not as a literal "Normal" class label.
_NORMAL_ALIASES = {"normal", "normal / ignored", "benign"}


def _feedback_label(value: str) -> str:
    return "BENIGN" if value.strip().lower() in _NORMAL_ALIASES else value.strip()


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
def submit_feedback(payload: FeedbackIn, db: Session = Depends(get_db)) -> FeedbackOut:
    alert = db.get(Alert, payload.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    label = _feedback_label(payload.validated_label)
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
