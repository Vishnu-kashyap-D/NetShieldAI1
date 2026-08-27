from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(String(36), index=True)

    window_start: Mapped[int] = mapped_column(Integer)
    window_end: Mapped[int] = mapped_column(Integer)
    source_file: Mapped[str] = mapped_column(String(255), index=True)

    actual_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actual_category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    predicted_label: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[float] = mapped_column(Float)

    anomaly_score: Mapped[float] = mapped_column(Float)
    anomaly_threshold: Mapped[float] = mapped_column(Float)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, index=True)
    pipeline_action: Mapped[str] = mapped_column(String(64))

    risk_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String(16), index=True)

    top_classifier_features: Mapped[str | None] = mapped_column(Text, nullable=True)
    top_anomaly_features: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Raw traffic feature vector for this window's last row, keyed by feature name.
    # Kept as JSON instead of ~76 individual columns; this is exactly the row shape
    # cyber_ai.feedback / cyber_ai.train expect when this alert is later validated.
    features: Mapped[dict] = mapped_column(JSON)

    ingested_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow, index=True)

    feedback: Mapped[list["Feedback"]] = relationship(back_populates="alert", cascade="all, delete-orphan")


class Feedback(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)

    validated_label: Mapped[str] = mapped_column(String(64))
    analyst: Mapped[str | None] = mapped_column(String(128), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    written_to_feedback_store: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    alert: Mapped["Alert"] = relationship(back_populates="feedback")


class TrainingRun(Base):
    __tablename__ = "training_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)  # running|completed|failed
    triggered_by: Mapped[str | None] = mapped_column(String(128), nullable=True)

    feedback_rows_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    started_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
