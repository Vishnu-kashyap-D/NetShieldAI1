from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import Alert
from app.schemas import StatsSummaryOut, TimeseriesPointOut

router = APIRouter(prefix="/stats", tags=["stats"], dependencies=[Depends(get_current_user)])


@router.get("/summary", response_model=StatsSummaryOut)
def summary(db: Session = Depends(get_db)) -> StatsSummaryOut:
    total = db.execute(select(func.count()).select_from(Alert)).scalar_one()
    anomaly_count = db.execute(
        select(func.count()).select_from(Alert).where(Alert.is_anomaly.is_(True))
    ).scalar_one()

    risk_rows = db.execute(select(Alert.risk_level, func.count()).group_by(Alert.risk_level)).all()
    category_rows = db.execute(select(Alert.predicted_label, func.count()).group_by(Alert.predicted_label)).all()

    return StatsSummaryOut(
        total_alerts=total,
        risk_level_counts={level: count for level, count in risk_rows},
        category_counts={label: count for label, count in category_rows},
        anomaly_count=anomaly_count,
    )


@router.get("/timeseries", response_model=list[TimeseriesPointOut])
def timeseries(
    minutes: int = Query(60, ge=1, le=1440, description="How many minutes of history to bucket."),
    bucket_seconds: int = Query(
        30, ge=1, le=3600,
        description="Bucket width in seconds. A fast stream-simulator run (a few seconds between "
        "chunks) needs a small width -- the default per-minute-style bucketing collapses a whole "
        "demo run into a single point.",
    ),
    db: Session = Depends(get_db),
) -> list[TimeseriesPointOut]:
    since = dt.datetime.utcnow() - dt.timedelta(minutes=minutes)
    bucket = func.from_unixtime(func.floor(func.unix_timestamp(Alert.ingested_at) / bucket_seconds) * bucket_seconds)
    rows = db.execute(
        select(
            bucket.label("bucket"),
            func.count().label("count"),
            func.sum(case((Alert.risk_level == "High", 1), else_=0)).label("high"),
            func.sum(case((Alert.risk_level == "Medium", 1), else_=0)).label("medium"),
            func.sum(case((Alert.risk_level == "Low", 1), else_=0)).label("low"),
        )
        .where(Alert.ingested_at >= since)
        .group_by("bucket")
        .order_by("bucket")
    ).all()
    return [
        TimeseriesPointOut(
            bucket=row.bucket, count=row.count, high=row.high or 0, medium=row.medium or 0, low=row.low or 0
        )
        for row in rows
    ]
