from __future__ import annotations

import logging

from sqlalchemy import Engine, func, inspect, select, text, update
from sqlalchemy.exc import DBAPIError

from app.feature_schema import feature_schema_version
from app.models import Alert, Feedback

logger = logging.getLogger("netshield.backend")

_BACKFILL_BATCH = 500


def run_migrations(engine: Engine) -> None:
    """Bring an already-existing database up to the current models, additively and idempotently.

    `Base.metadata.create_all` only creates *missing tables*; it never alters a table that's
    already there, so a column or constraint added to a model later never reaches a database that
    was created earlier. There's no Alembic in this project, so this runs the few changes that
    matter, each guarded by an inspection of the live schema so a re-run (every startup) is a
    no-op and a brand-new database (where create_all already built everything) is untouched.
    """
    _add_alert_schema_version_column(engine)
    _backfill_alert_schema_versions(engine)
    _enforce_one_feedback_per_alert(engine)


def _has_alert_schema_version_column(engine: Engine) -> bool:
    return "feature_schema_version" in {column["name"] for column in inspect(engine).get_columns(Alert.__tablename__)}


def _add_alert_schema_version_column(engine: Engine) -> None:
    if _has_alert_schema_version_column(engine):
        return
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN feature_schema_version VARCHAR(16) NULL"))
    except DBAPIError:
        # `uvicorn --workers N` starts N processes that all run this at once against a database that
        # still needs the change: one wins, the rest get "duplicate column". That's success, not failure.
        if _has_alert_schema_version_column(engine):
            return
        raise
    logger.info("Migration: added alerts.feature_schema_version.")


def _backfill_alert_schema_versions(engine: Engine) -> None:
    """Version every pre-existing alert from its own stored feature keys.

    Alert.features is keyed by feature name, so an old row describes its own feature set --
    the backfill is exact, not a guess that "old rows used the current features".
    """
    table = Alert.__table__
    updated = 0
    while True:
        with engine.begin() as conn:
            rows = conn.execute(
                select(table.c.id, table.c.features)
                .where(table.c.feature_schema_version.is_(None))
                .limit(_BACKFILL_BATCH)
            ).all()
            if not rows:
                break
            for alert_id, features in rows:
                version = feature_schema_version(features.keys()) if isinstance(features, dict) else "unknown"
                conn.execute(update(table).where(table.c.id == alert_id).values(feature_schema_version=version))
            updated += len(rows)
    if updated:
        logger.info("Migration: backfilled feature_schema_version on %d existing alert(s).", updated)


def _feedback_alert_id_is_unique(engine: Engine) -> bool:
    inspector = inspect(engine)
    return any(
        constraint["column_names"] == ["alert_id"] for constraint in inspector.get_unique_constraints(Feedback.__tablename__)
    ) or any(
        index.get("unique") and index["column_names"] == ["alert_id"] for index in inspector.get_indexes(Feedback.__tablename__)
    )


def _enforce_one_feedback_per_alert(engine: Engine) -> None:
    if _feedback_alert_id_is_unique(engine):
        return
    try:
        _dedupe_and_add_unique_index(engine)
    except DBAPIError:
        if _feedback_alert_id_is_unique(engine):  # another worker got there first (see above)
            return
        raise


def _dedupe_and_add_unique_index(engine: Engine) -> None:
    table = Feedback.__table__
    with engine.begin() as conn:
        # A unique index can't be built over existing duplicates. Keep each alert's newest row (the
        # analyst's latest word on it) and drop the superseded ones -- but say so loudly, since
        # this is the one place a migration deletes data.
        duplicated = conn.execute(
            select(table.c.alert_id, func.max(table.c.id))
            .group_by(table.c.alert_id)
            .having(func.count() > 1)
        ).all()
        removed = 0
        for alert_id, newest_id in duplicated:
            result = conn.execute(table.delete().where(table.c.alert_id == alert_id, table.c.id < newest_id))
            removed += result.rowcount or 0
        if removed:
            logger.warning(
                "Migration: removed %d superseded duplicate feedback row(s) across %d alert(s), keeping each "
                "alert's newest. (Rows already written to the retraining CSV are not touched.)",
                removed, len(duplicated),
            )
        conn.execute(text("CREATE UNIQUE INDEX uq_feedback_alert_id ON feedback (alert_id)"))
    logger.info("Migration: added unique index uq_feedback_alert_id on feedback.alert_id.")
