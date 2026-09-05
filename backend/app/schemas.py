from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    batch_id: str
    window_start: int
    window_end: int
    source_file: str
    actual_label: str | None
    actual_category: str | None
    predicted_label: str
    confidence: float
    anomaly_score: float
    anomaly_threshold: float
    is_anomaly: bool
    pipeline_action: str
    risk_score: float
    risk_level: str
    top_classifier_features: str | None
    top_anomaly_features: str | None
    ingested_at: dt.datetime


class AlertDetailOut(AlertOut):
    features: dict


class AlertListOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AlertOut]


class IngestSummaryOut(BaseModel):
    batch_id: str
    source: str
    windows_scored: int
    anomalous_windows: int
    alerts_written: int
    risk_level_counts: dict[str, int]
    predicted_label_counts: dict[str, int]


class StatsSummaryOut(BaseModel):
    total_alerts: int
    risk_level_counts: dict[str, int]
    category_counts: dict[str, int]
    anomaly_count: int


class TimeseriesPointOut(BaseModel):
    bucket: dt.datetime
    count: int
    high: int
    medium: int
    low: int


class FeedbackIn(BaseModel):
    alert_id: int
    validated_label: str
    analyst: str | None = None
    notes: str | None = None


class FeedbackOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    validated_label: str
    analyst: str | None
    written_to_feedback_store: bool
    created_at: dt.datetime


class RetrainTriggerIn(BaseModel):
    triggered_by: str | None = None


class TrainingRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    triggered_by: str | None
    feedback_rows_used: int | None
    metrics: dict | None
    error: str | None
    started_at: dt.datetime
    finished_at: dt.datetime | None


class ChatMessageIn(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class ChatIn(BaseModel):
    question: str
    # Prior turns of this same conversation, oldest first -- optional, only used to give the
    # LLM fallback path multi-turn context. The deterministic matcher is always stateless.
    history: list[ChatMessageIn] = []


class ChatSourcesOut(BaseModel):
    prediction: bool
    shap: bool
    feature_values: bool
    glossary: bool


class ChatOut(BaseModel):
    answer: str
    sources: ChatSourcesOut


class HealthOut(BaseModel):
    status: str
    model_loaded: bool
    feature_count: int | None
    artifacts_dir: str
