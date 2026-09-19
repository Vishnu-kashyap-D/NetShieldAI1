from __future__ import annotations

import math

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.chat_service import answer_project_question, answer_question, build_alert_context
from app.config import settings
from app.database import get_db
from app.models import Alert, User
from app.ratelimit import SlidingWindowLimiter
from app.schemas import ChatIn, ChatOut, ChatSourcesOut

# One shared budget per signed-in user across BOTH chatbots -- either can end up calling the paid
# LLM, and a Viewer (the least-privileged role) can reach both, so this is the cost backstop.
_chat_limiter = SlidingWindowLimiter(settings.chat_max_requests_per_minute, 60)


def enforce_chat_rate_limit(user: User = Depends(get_current_user)) -> None:
    wait = _chat_limiter.acquire(str(user.id))
    if wait > 0:
        seconds = math.ceil(wait)
        raise HTTPException(
            status_code=429,
            detail=f"You're sending chat messages too quickly. Try again in {seconds} second{'s' if seconds != 1 else ''}.",
            headers={"Retry-After": str(seconds)},
        )


router = APIRouter(
    prefix="/alerts", tags=["chat"], dependencies=[Depends(get_current_user), Depends(enforce_chat_rate_limit)]
)
project_router = APIRouter(
    prefix="/chat", tags=["chat"], dependencies=[Depends(get_current_user), Depends(enforce_chat_rate_limit)]
)


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
