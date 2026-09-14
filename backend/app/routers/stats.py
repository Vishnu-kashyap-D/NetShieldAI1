from __future__ import annotations

import datetime as dt
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.config import settings
from app.database import get_db
from app.models import Alert
from app.schemas import ModelMetricsOut, PerClassMetricOut, StatsSummaryOut, TimeseriesPointOut

router = APIRouter(prefix="/stats", tags=["stats"], dependencies=[Depends(get_current_user)])

_NON_CLASS_KEYS = {"accuracy", "macro avg", "weighted avg"}


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


@router.get("/model-metrics", response_model=ModelMetricsOut)
def model_metrics() -> ModelMetricsOut:
    """Real evaluation numbers from the last training run, for the Analytics page's model card --
    the actual macro-F1/per-class breakdown is meant to be visible proactively, not something a
    reviewer has to ask about or compute by hand from a report they weren't given."""
    metrics_path = settings.reports_dir / "training_metrics.json"
    if not metrics_path.exists():
        raise HTTPException(status_code=404, detail=f"No training_metrics.json found at {metrics_path}.")

    with open(metrics_path, encoding="utf-8") as f:
        data = json.load(f)

    bilstm_report = data["bilstm_classifier"]["classification_report"]
    per_class = [
        PerClassMetricOut(
            category=category,
            precision=values["precision"],
            recall=values["recall"],
            f1=values["f1-score"],
            support=int(values["support"]),
        )
        for category, values in bilstm_report.items()
        if category not in _NON_CLASS_KEYS
    ]
    ae_report = data["autoencoder"]["classification_report"]
    ae_threshold = data["autoencoder"]["threshold_report"]
    hybrid = data["hybrid_risk"]

    return ModelMetricsOut(
        trained_at=dt.datetime.fromtimestamp(metrics_path.stat().st_mtime).isoformat(),
        bilstm_accuracy=bilstm_report["accuracy"],
        bilstm_macro_f1=bilstm_report["macro avg"]["f1-score"],
        bilstm_weighted_f1=bilstm_report["weighted avg"]["f1-score"],
        bilstm_per_class=per_class,
        autoencoder_accuracy=ae_report["accuracy"],
        autoencoder_balanced_accuracy=ae_threshold["balanced_accuracy"],
        autoencoder_true_positive_rate=ae_threshold["true_positive_rate"],
        autoencoder_true_negative_rate=ae_threshold["true_negative_rate"],
        hybrid_false_positive_rate=hybrid["false_positive_rate"],
        hybrid_false_negative_rate=hybrid["false_negative_rate"],
    )
