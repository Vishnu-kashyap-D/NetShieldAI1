from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import Alert
from app.schemas import AlertDetailOut, AlertListOut, AlertOut

# Every route here requires a valid session, no specific role -- any authenticated user
# (including Viewer) can read alerts.
router = APIRouter(prefix="/alerts", tags=["alerts"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=AlertListOut)
def list_alerts(
    risk_level: str | None = Query(None, description="Low | Medium | High"),
    category: str | None = Query(None, description="Predicted attack category"),
    source_file: str | None = None,
    batch_id: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> AlertListOut:
    stmt = select(Alert)
    if risk_level:
        stmt = stmt.where(Alert.risk_level == risk_level)
    if category:
        stmt = stmt.where(Alert.predicted_label == category)
    if source_file:
        stmt = stmt.where(Alert.source_file == source_file)
    if batch_id:
        stmt = stmt.where(Alert.batch_id == batch_id)

    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    stmt = stmt.order_by(Alert.ingested_at.desc(), Alert.id.desc()).offset(offset).limit(limit)
    items = db.execute(stmt).scalars().all()
    return AlertListOut(total=total, limit=limit, offset=offset, items=[AlertOut.model_validate(a) for a in items])


@router.get("/{alert_id}", response_model=AlertDetailOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertDetailOut:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertDetailOut.model_validate(alert)
