from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import CorrelatedCampaign
from app.schemas import CampaignListOut, CampaignOut

# Any signed-in user can read campaigns, like alerts: they are derived from the same scored windows.
router = APIRouter(prefix="/campaigns", tags=["campaigns"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=CampaignListOut)
def list_campaigns(
    source_file: str | None = None,
    batch_id: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> CampaignListOut:
    """Sustained activity found by the cross-window layer (cyber_ai/correlation.py): runs of consecutive windows
    the classifier kept reading as the same `category` at very high confidence, typically activity the anomaly
    gate never flagged. Newest first. `alerted_windows` of a campaign's `windows` raised an alert on their own;
    the rest were only visible in aggregate."""
    stmt = select(CorrelatedCampaign)
    if source_file:
        stmt = stmt.where(CorrelatedCampaign.source_file == source_file)
    if batch_id:
        stmt = stmt.where(CorrelatedCampaign.batch_id == batch_id)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(
        stmt.order_by(CorrelatedCampaign.detected_at.desc(), CorrelatedCampaign.id.desc()).offset(offset).limit(limit)
    ).scalars().all()
    return CampaignListOut(total=total, limit=limit, offset=offset, items=[CampaignOut.model_validate(row) for row in rows])
