from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: str
    role: str


class LoginIn(BaseModel):
    email: EmailStr
    # Bounded (same cap as RegisterIn) so a multi-megabyte "password" is rejected up front instead
    # of being copied around and handed to bcrypt.
    password: str = Field(max_length=128)


class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: str


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
    # Which feature set `features` was scored under (app.feature_schema); None only for a row the
    # startup migration hasn't reached yet.
    feature_schema_version: str | None = None


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
    duplicates_skipped: int
    # Cross-window "campaigns" found in this upload (see GET /api/campaigns): sustained activity that no single
    # window alerts on. Counted, not deduplicated -- a re-upload reports the same ones it found the first time.
    campaigns_found: int = 0
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


class PerClassMetricOut(BaseModel):
    category: str
    precision: float
    recall: float
    f1: float
    support: int


class ModelMetricsOut(BaseModel):
    """Real evaluation numbers from the last training run (reports/training_metrics.json),
    surfaced in the dashboard so the model's actual accuracy/macro-F1/per-class breakdown is
    visible up front rather than something a panelist has to ask about or compute by hand."""

    trained_at: str | None
    bilstm_accuracy: float
    bilstm_macro_f1: float
    bilstm_weighted_f1: float
    bilstm_per_class: list[PerClassMetricOut]
    autoencoder_accuracy: float
    autoencoder_balanced_accuracy: float
    autoencoder_true_positive_rate: float
    autoencoder_true_negative_rate: float
    hybrid_false_positive_rate: float
    hybrid_false_negative_rate: float


class DriftBinOut(BaseModel):
    bin: int
    expected: float
    live: float


class DriftOut(BaseModel):
    """Is ordinary traffic still scoring like the validation traffic the risk thresholds were calibrated on?"""

    # unavailable (no reference for this model) | insufficient_data | stable | watch | drifting
    status: str
    message: str
    period_hours: int
    # Population Stability Index of the unflagged windows' score distribution vs the validation reference;
    # None until there are enough windows. < 0.1 stable, 0.1-0.25 watch, > 0.25 drifting.
    psi: float | None = None
    psi_watch: float
    psi_drifting: float
    windows: int = 0
    quiet_windows: int = 0
    flag_rate: float | None = None
    reference_flag_rate: float | None = None
    # Live flag rate / validation false-alarm rate. Context only: real attacks raise it legitimately.
    flag_rate_ratio: float | None = None
    batches_considered: int = 0
    # Ingests in the period scored under an earlier model (different bins), left out of the comparison.
    batches_excluded: int = 0
    bins: list[DriftBinOut] = []


class CampaignOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    batch_id: str
    source_file: str
    category: str
    first_window: int
    last_window: int
    windows: int
    alerted_windows: int
    mean_confidence: float
    detected_at: dt.datetime


class CampaignListOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[CampaignOut]


class FeedbackIn(BaseModel):
    alert_id: int
    validated_label: str
    # Accepted so older clients don't 422, but IGNORED: the server records the signed-in user's own name, so a
    # label can't be attributed to someone else (same rule as a retrain's `triggered_by`).
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


# Chat input limits. Both chatbots can forward this text to a paid LLM, so unbounded input is
# unbounded cost. A message is capped well above anything a person types (a whole assistant answer,
# up to the LLM's 1024-token output cap, is a "message" too when it's sent back as history), and the
# frontend (src/constants/chat.ts) mirrors these so the UI never lets someone compose a message this
# API would reject -- it also sends fewer history turns than the API's ceiling, so a long
# conversation never trips the limit.
CHAT_QUESTION_MAX_CHARS = 2000
CHAT_MESSAGE_MAX_CHARS = 8000
CHAT_HISTORY_MAX_TURNS = 40


class ChatMessageIn(BaseModel):
    role: str = Field(max_length=16)  # "user" | "assistant"
    content: str = Field(max_length=CHAT_MESSAGE_MAX_CHARS)


class ChatIn(BaseModel):
    question: str = Field(max_length=CHAT_QUESTION_MAX_CHARS)
    # Prior turns of this same conversation, oldest first -- optional, only used to give the
    # LLM fallback path multi-turn context. The deterministic matcher is always stateless.
    history: list[ChatMessageIn] = Field(default_factory=list, max_length=CHAT_HISTORY_MAX_TURNS)


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
