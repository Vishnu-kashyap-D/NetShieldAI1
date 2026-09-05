from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.chat_service import answer_question, build_alert_context
from app.database import get_db
from app.models import Alert
from app.schemas import ChatIn, ChatOut, ChatSourcesOut

router = APIRouter(prefix="/alerts", tags=["chat"])


@router.post("/{alert_id}/chat", response_model=ChatOut)
def chat_about_alert(alert_id: int, payload: ChatIn, db: Session = Depends(get_db)) -> ChatOut:
    """Explainability chatbot for one alert.

    Grounded entirely in this alert's own stored prediction/SHAP/feature data (see
    build_alert_context) -- never touches model files, preprocessing artifacts, or any other
    alert. Uses the existing alerts table as the only source of truth; no second storage system.
    """
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    context = build_alert_context(alert)
    history = [{"role": turn.role, "content": turn.content} for turn in payload.history]
    answer = answer_question(payload.question, context, history)

    return ChatOut(answer=answer.text, sources=ChatSourcesOut(**answer.sources.as_dict()))
