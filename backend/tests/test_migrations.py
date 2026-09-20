"""4.1 / 4.5 -- the startup migration upgrades an already-existing database, additively and idempotently."""
from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.feature_schema import feature_schema_version
from app.migrations import run_migrations
import app.models  # noqa: F401
from app.models import Feedback


def _legacy_engine():
    """A database as it looked before Phase 4: no alerts.feature_schema_version, no unique feedback index."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[t for t in Base.metadata.sorted_tables if t.name != "feedback"])
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE alerts DROP COLUMN feature_schema_version"))
        conn.execute(text(
            "CREATE TABLE feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL REFERENCES alerts(id), "
            "validated_label VARCHAR(64) NOT NULL, analyst VARCHAR(128), notes TEXT, "
            "written_to_feedback_store BOOLEAN, created_at DATETIME)"
        ))
        conn.execute(text("CREATE INDEX ix_feedback_alert_id ON feedback (alert_id)"))
    return engine


def _insert_alert(conn, features: dict) -> int:
    result = conn.execute(
        text(
            "INSERT INTO alerts (batch_id, window_start, window_end, source_file, predicted_label, confidence, "
            "anomaly_score, anomaly_threshold, is_anomaly, pipeline_action, risk_score, risk_level, features, ingested_at) "
            "VALUES ('b', 0, 9, 't.csv', 'Normal', 0, 0, 0, 0, 'x', 0, 'Low', :f, CURRENT_TIMESTAMP)"
        ),
        {"f": json.dumps(features)},
    )
    return result.lastrowid


def test_legacy_database_is_upgraded():
    engine = _legacy_engine()
    with engine.begin() as conn:
        a1 = _insert_alert(conn, {"x": 1, "y": 2})
        a2 = _insert_alert(conn, {"x": 1, "y": 2, "z": 3})
        for alert_id, label in [(a1, "old"), (a1, "newest"), (a2, "only")]:
            conn.execute(text("INSERT INTO feedback (alert_id, validated_label) VALUES (:a, :l)"), {"a": alert_id, "l": label})

    run_migrations(engine)

    with engine.connect() as conn:
        versions = dict(conn.execute(text("SELECT id, feature_schema_version FROM alerts")).all())
        assert versions[a1] == feature_schema_version(["x", "y"])  # backfilled from the row's own keys
        assert versions[a2] == feature_schema_version(["x", "y", "z"])
        labels = dict(conn.execute(text("SELECT alert_id, validated_label FROM feedback")).all())
        assert labels == {a1: "newest", a2: "only"}  # superseded duplicate dropped, newest kept
    unique = [i for i in inspect(engine).get_indexes("feedback") if i.get("unique")]
    assert [i["column_names"] for i in unique] == [["alert_id"]]

    with engine.begin() as conn, pytest.raises(IntegrityError):
        conn.execute(text("INSERT INTO feedback (alert_id, validated_label) VALUES (:a, 'dup')"), {"a": a1})


def test_migrating_twice_changes_nothing():
    engine = _legacy_engine()
    with engine.begin() as conn:
        _insert_alert(conn, {"x": 1})
    run_migrations(engine)
    with engine.connect() as conn:
        snapshot = conn.execute(text("SELECT id, feature_schema_version FROM alerts")).all()
    run_migrations(engine)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT id, feature_schema_version FROM alerts")).all() == snapshot


def test_a_fresh_database_needs_no_migration(sqlite_engine):
    before = inspect(sqlite_engine).get_unique_constraints("feedback")
    run_migrations(sqlite_engine)
    assert inspect(sqlite_engine).get_unique_constraints("feedback") == before != []
    assert Feedback.__table__.c.alert_id.nullable is False


def test_losing_the_startup_race_to_another_worker_is_not_an_error(monkeypatch):
    """`uvicorn --workers 2`: both workers see "column/index missing", one wins the DDL, the other's
    DDL raises. The loser must carry on -- not crash the worker at startup."""
    from sqlalchemy import event

    import app.migrations as migrations

    engine = _legacy_engine()
    run_migrations(engine)  # "the other worker" already applied everything

    attempted = []

    @event.listens_for(engine, "before_cursor_execute")
    def record_ddl(conn, cursor, statement, *args):
        if statement.startswith(("ALTER TABLE", "CREATE UNIQUE INDEX")):
            attempted.append(statement.split()[0])

    real_inspect = migrations.inspect
    state = {"columns_seen": False, "indexes_seen": False}

    class StaleOnceInspector:
        """Reports the pre-migration schema on the first look (what the loser saw), the truth afterwards."""

        def __init__(self, real):
            self.real = real

        def get_columns(self, table):
            columns = self.real.get_columns(table)
            if table == "alerts" and not state["columns_seen"]:
                state["columns_seen"] = True
                return [c for c in columns if c["name"] != "feature_schema_version"]
            return columns

        def get_unique_constraints(self, table):
            return self.real.get_unique_constraints(table) if state["indexes_seen"] else []

        def get_indexes(self, table):
            indexes = self.real.get_indexes(table)
            if state["indexes_seen"]:
                return indexes
            state["indexes_seen"] = True
            return [i for i in indexes if not i.get("unique")]

    monkeypatch.setattr(migrations, "inspect", lambda engine_: StaleOnceInspector(real_inspect(engine_)))

    run_migrations(engine)  # each DDL below is rejected as already-applied -- and must be swallowed

    assert attempted == ["ALTER", "CREATE"]  # both racing statements really were sent and really failed
