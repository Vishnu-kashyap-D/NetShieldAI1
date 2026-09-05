from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.chat_service import answer_project_question, answer_question, build_alert_context
from app.database import get_db
from app.models import Alert
from app.schemas import ChatIn, ChatOut, ChatSourcesOut

router = APIRouter(prefix="/alerts", tags=["chat"], dependencies=[Depends(get_current_user)])
project_router = APIRouter(prefix="/chat", tags=["chat"], dependencies=[Depends(get_current_user)])


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


@project_router.post("", response_model=ChatOut)
def chat_about_project(payload: ChatIn) -> ChatOut:
    """General project/threat Q&A -- the sidebar's "SHAP" page. Not tied to any alert; see
    app.chat_service.answer_project_question for the fixed project fact sheet and the
    off-topic-refusal system prompt this runs under (Gemini-backed, separate key from the
    per-alert assistant above).
    """
    history = [{"role": turn.role, "content": turn.content} for turn in payload.history]
    answer = answer_project_question(payload.question, history)
    return ChatOut(answer=answer.text, sources=ChatSourcesOut(**answer.sources.as_dict()))
