from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
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
    # Fingerprint of the feature *set* `features` was scored under (app.feature_schema). Nullable
    # only because rows created before this column existed are backfilled by app.migrations.
    feature_schema_version: Mapped[str | None] = mapped_column(String(16), nullable=True)

    ingested_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow, index=True)

    feedback: Mapped[list["Feedback"]] = relationship(back_populates="alert", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(60))  # bcrypt hashes are always 60 chars
    # One of app.auth.Role's values -- assigned at account creation, never chosen by the user
    # at login. Real RBAC means access level is a server-side fact about the account, not
    # something a client can self-select (that's what the old cosmetic login's role dropdown did).
    role: Mapped[str] = mapped_column(String(32), index=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    sessions: Mapped[list["UserSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")


# Named UserSession, not Session -- every router already imports sqlalchemy.orm.Session as the
# DB-session type, and shadowing that name with this model would be a real bug waiting to happen.
class UserSession(Base):
    __tablename__ = "sessions"

    # sha256 hex of the opaque random token (see app.auth._hash_token / create_session) -- NOT the
    # token itself. The raw token exists only in the browser's cookie, so a copy of this table
    # can't be replayed as live logins. Not an auto-increment id: the lookup key must be derived
    # from something unguessable, not just unique. (sha256 hexdigest is exactly 64 chars.)
    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime, index=True)

    user: Mapped["User"] = relationship(back_populates="sessions")


class Feedback(Base):
    __tablename__ = "feedback"
    # One validated label per alert: resubmitting *updates* it (routers/feedback.py) instead of
    # stacking up contradictory rows -- each of which used to be a separate retraining row.
    # (The constraint's index also serves the foreign key, so no separate index=True is needed.)
    __table_args__ = (UniqueConstraint("alert_id", name="uq_feedback_alert_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"))

    validated_label: Mapped[str] = mapped_column(String(64))
    analyst: Mapped[str | None] = mapped_column(String(128), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    written_to_feedback_store: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    alert: Mapped["Alert"] = relationship(back_populates="feedback")


class ScoreBatch(Base):
    """What one ingest's scoring looked like, over ALL its windows (not just the stored Medium/High ones).

    `alerts` only keeps windows worth alerting on, so it can't show whether ordinary traffic has started
    scoring differently. This keeps a tiny histogram per ingest instead -- the counts of windows falling in
    each of the drift reference's score bins (cyber_ai/drift.py) -- which is all drift monitoring needs.
    """

    __tablename__ = "score_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(String(36), unique=True)
    source_file: Mapped[str] = mapped_column(String(255))
    # Fingerprint of the drift reference the counts were binned under: counts from before a retrain (a
    # different model, different bins) must never be compared with the new reference.
    reference_id: Mapped[str] = mapped_column(String(16), index=True)
    windows_scored: Mapped[int] = mapped_column(Integer)
    flagged_windows: Mapped[int] = mapped_column(Integer)
    quiet_bin_counts: Mapped[list] = mapped_column(JSON)
    ingested_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow, index=True)


class CorrelatedCampaign(Base):
    """A long run of consecutive windows the classifier kept reading as one category at very high confidence
    (cyber_ai/correlation.py) -- typically activity the anomaly gate never flagged, so no per-window alert exists
    for most of it. Reported beside the alerts; never replaces them."""

    __tablename__ = "campaigns"
    __table_args__ = (UniqueConstraint("batch_id", "source_file", "first_window", name="uq_campaign_span"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(String(36), index=True)
    source_file: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)   # what the run consistently looked like
    first_window: Mapped[int] = mapped_column(Integer)      # row where the first window of the run starts
    last_window: Mapped[int] = mapped_column(Integer)       # row where the last window of the run ends
    windows: Mapped[int] = mapped_column(Integer)
    alerted_windows: Mapped[int] = mapped_column(Integer)   # of those, windows that were Medium/High on their own
    mean_confidence: Mapped[float] = mapped_column(Float)   # classifier confidence, averaged over the run
    detected_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow, index=True)


class TrainingRun(Base):
    __tablename__ = "training_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)  # running|completed|rejected|failed
    triggered_by: Mapped[str | None] = mapped_column(String(128), nullable=True)

    feedback_rows_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    log_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    started_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
