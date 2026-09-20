"""5.1 -- retraining: the 409 concurrency guard, the quality gate, and the job's success/failure paths."""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from conftest import login
from app.config import settings
from app.models import TrainingRun
from app.routers import retrain as retrain_router

ADMIN = "admin@example.com"


def metrics(bilstm_accuracy: float, ae_balanced_accuracy: float) -> dict:
    return {
        "bilstm_classifier": {"classification_report": {"accuracy": bilstm_accuracy}},
        "autoencoder": {"threshold_report": {"balanced_accuracy": ae_balanced_accuracy}},
    }


# --- the API: trigger + the concurrency guard ------------------------------------------------------


@pytest.fixture()
def trigger(api, session_factory, monkeypatch):
    """Retrain trigger with the background thread's work replaced by a no-op, so the run stays 'running'."""
    monkeypatch.setattr(retrain_router, "_run_training", lambda run_id: None)
    login(api, ADMIN)
    return lambda: api.post("/api/retrain", json={})


def test_triggering_starts_a_running_run_attributed_to_the_caller(trigger, session_factory):
    response = trigger()
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "running"
    assert body["triggered_by"] == "admin"  # the authenticated user, from the session
    with session_factory() as db:
        assert db.get(TrainingRun, body["id"]).status == "running"


def test_the_caller_cannot_attribute_a_run_to_someone_else(api, session_factory, monkeypatch):
    monkeypatch.setattr(retrain_router, "_run_training", lambda run_id: None)
    login(api, ADMIN)
    response = api.post("/api/retrain", json={"triggered_by": "Somebody Else"})
    assert response.json()["triggered_by"] == "admin"


def test_a_second_trigger_while_one_is_running_is_a_409(trigger, session_factory):
    first = trigger().json()
    second = trigger()
    assert second.status_code == 409
    assert str(first["id"]) in second.json()["detail"]
    with session_factory() as db:
        assert len(db.execute(select(TrainingRun)).scalars().all()) == 1  # no second run was created


def test_a_new_run_is_allowed_once_the_previous_one_has_finished(trigger, session_factory):
    first = trigger().json()
    with session_factory() as db:
        db.get(TrainingRun, first["id"]).status = "completed"
        db.commit()
    assert trigger().status_code == 200


@pytest.mark.parametrize("finished_status", ["failed", "rejected", "completed"])
def test_only_a_running_run_blocks_a_new_one(trigger, session_factory, finished_status):
    with session_factory() as db:
        db.add(TrainingRun(status=finished_status))
        db.commit()
    assert trigger().status_code == 200


def test_history_lists_runs_newest_first_and_a_missing_run_is_404(trigger, api):
    trigger()
    assert len(api.get("/api/retrain").json()) == 1
    assert api.get("/api/retrain/9999").status_code == 404


def test_the_feedback_row_count_recorded_on_the_run_excludes_the_header(api, tmp_path, monkeypatch):
    store = tmp_path / "fb.csv"
    store.write_text("a,b,Label\n1,2,x\n3,4,y\n", encoding="utf-8")
    assert retrain_router._count_feedback_rows(store) == 2
    assert retrain_router._count_feedback_rows(tmp_path / "missing.csv") is None


# --- the quality gate's decision -------------------------------------------------------------------


class TestShouldDeploy:
    def test_an_improved_model_deploys(self):
        ok, reason = retrain_router._should_deploy(metrics(0.98, 0.95), metrics(0.97, 0.94))
        assert ok and "0.9800" in reason

    def test_an_identical_model_deploys(self):
        assert retrain_router._should_deploy(metrics(0.97, 0.94), metrics(0.97, 0.94))[0]

    def test_a_dip_within_the_tolerance_deploys(self):
        assert retrain_router._should_deploy(metrics(0.965, 0.935), metrics(0.97, 0.94))[0]

    def test_a_classifier_regression_beyond_tolerance_is_rejected(self):
        ok, reason = retrain_router._should_deploy(metrics(0.90, 0.94), metrics(0.97, 0.94))
        assert not ok and "BiLSTM" in reason

    def test_an_autoencoder_regression_beyond_tolerance_is_rejected(self):
        ok, reason = retrain_router._should_deploy(metrics(0.97, 0.80), metrics(0.97, 0.94))
        assert not ok and "Autoencoder" in reason

    def test_a_win_on_one_metric_does_not_excuse_a_loss_on_the_other(self):
        assert not retrain_router._should_deploy(metrics(0.999, 0.80), metrics(0.97, 0.94))[0]

    @pytest.mark.parametrize("broken", [{}, {"bilstm_classifier": {}}, {"autoencoder": None}])
    def test_metrics_in_an_unexpected_shape_deploy_by_default(self, broken):
        assert retrain_router._should_deploy(broken, metrics(0.97, 0.94))[0]
        assert retrain_router._should_deploy(metrics(0.97, 0.94), broken)[0]


# --- the whole background job ----------------------------------------------------------------------


@pytest.fixture()
def job(session_factory, tmp_path, monkeypatch):
    """Runs the real `_run_training` against a scratch artifacts dir, a fake `cyber_ai.train` subprocess
    and an in-memory DB, recording whether the live model was told to reload."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "weights.txt").write_text("OLD MODEL", encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()

    monkeypatch.setattr(settings, "artifacts_dir", artifacts)
    monkeypatch.setattr(settings, "reports_dir", reports)
    monkeypatch.setattr(settings, "training_logs_dir", tmp_path / "logs")
    monkeypatch.setattr(settings, "feedback_store", tmp_path / "feedback.csv")
    monkeypatch.setattr(retrain_router, "SessionLocal", session_factory)

    reloads: list[str] = []
    monkeypatch.setattr(retrain_router, "reload_engine", lambda: reloads.append("reload"))

    state = SimpleNamespace(returncode=0, new_metrics=metrics(0.98, 0.95), write_metrics=True, raise_error=None)

    def fake_train(command, **kwargs):
        assert command[:3] == [sys.executable, "-m", "cyber_ai.train"]
        if state.raise_error:
            raise state.raise_error
        # like the real trainer, overwrite the live artifacts in place while it runs
        (artifacts / "weights.txt").write_text("NEW MODEL", encoding="utf-8")
        if state.write_metrics:
            (reports / "training_metrics.json").write_text(json.dumps(state.new_metrics), encoding="utf-8")
        return SimpleNamespace(returncode=state.returncode)

    monkeypatch.setattr(retrain_router.subprocess, "run", fake_train)

    def run(baseline: dict | None = None):
        with session_factory() as db:
            if baseline is not None:
                db.add(TrainingRun(status="completed", metrics=baseline))
            current = TrainingRun(status="running")
            db.add(current)
            db.commit()
            run_id = current.id
        retrain_router._run_training(run_id)
        with session_factory() as db:
            return db.get(TrainingRun, run_id)

    return SimpleNamespace(run=run, state=state, reloads=reloads, weights=artifacts / "weights.txt")


def test_the_first_ever_successful_run_deploys(job):
    result = job.run(baseline=None)
    assert result.status == "completed"
    assert job.reloads == ["reload"]
    assert job.weights.read_text(encoding="utf-8") == "NEW MODEL"
    assert result.metrics == job.state.new_metrics and result.finished_at is not None


def test_a_better_model_is_deployed_and_the_engine_reloaded(job):
    result = job.run(baseline=metrics(0.96, 0.93))
    assert result.status == "completed"
    assert job.reloads == ["reload"]
    assert job.weights.read_text(encoding="utf-8") == "NEW MODEL"


def test_a_worse_model_is_rejected_and_the_old_artifacts_are_restored(job):
    job.state.new_metrics = metrics(0.70, 0.95)
    result = job.run(baseline=metrics(0.97, 0.94))
    assert result.status == "rejected"
    assert "quality gate" in result.error and "BiLSTM" in result.error
    assert job.reloads == []                                              # the live model is untouched...
    assert job.weights.read_text(encoding="utf-8") == "OLD MODEL"         # ...and so are the files on disk


def test_a_failing_trainer_marks_the_run_failed_and_deploys_nothing(job):
    job.state.returncode = 1
    result = job.run(baseline=metrics(0.97, 0.94))
    assert result.status == "failed"
    assert "exited with code 1" in result.error
    assert job.reloads == []


def test_a_trainer_that_writes_no_metrics_file_is_a_failure(job):
    job.state.write_metrics = False
    result = job.run(baseline=metrics(0.97, 0.94))
    assert result.status == "failed"
    assert "training_metrics.json" in result.error
    assert job.reloads == []


def test_an_unexpected_exception_is_recorded_not_lost_in_the_thread(job):
    job.state.raise_error = OSError("disk full")
    result = job.run()
    assert result.status == "failed" and "disk full" in result.error


def test_only_completed_runs_count_as_the_baseline(job, session_factory):
    """A rejected run's (worse) metrics must not become the bar the next run is judged against."""
    with session_factory() as db:
        db.add(TrainingRun(status="rejected", metrics=metrics(0.10, 0.10)))
        db.commit()
    job.state.new_metrics = metrics(0.70, 0.95)
    result = job.run(baseline=metrics(0.97, 0.94))
    assert result.status == "rejected"  # judged against the 0.97 completed run, not the 0.10 rejected one
