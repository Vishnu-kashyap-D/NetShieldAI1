"""The training-feedback snapshot (cyber_ai/training_feedback.py): a model's held-out split must be
rebuildable from the feedback rows it was actually trained on, not from today's (longer) feedback store."""
from __future__ import annotations

from pathlib import Path

import pandas as pd

import app.config  # noqa: F401  (puts the repo root, and so cyber_ai, on sys.path)
from cyber_ai import holdout
from cyber_ai.training_feedback import (
    SNAPSHOT_DIRNAME,
    install_feedback_snapshot,
    stage_feedback_snapshot,
    training_feedback_csvs,
)


def _csv(path: Path, labels: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame({"Flow Duration": range(len(labels)), "Label": labels}).to_csv(path, index=False)
    return path


def _preprocessing(feedback_csvs: list[str]) -> dict:
    return {"config": {"data": {"feedback_csvs": feedback_csvs}}}


def test_staging_copies_each_file_keeping_its_name_and_order(tmp_path):
    a = _csv(tmp_path / "live" / "validated_traffic.csv", ["BENIGN", "DDoS"])
    b = _csv(tmp_path / "other" / "validated_traffic.csv", ["Bot"])  # same name, different file
    staged = stage_feedback_snapshot([a, tmp_path / "missing.csv", b], tmp_path / "stage")

    # The name is kept (it becomes the rows' source_file); slots keep two same-named files apart; a
    # missing file is skipped exactly like load_cicids2017 skips it.
    assert [p.relative_to(tmp_path / "stage").as_posix() for p in staged] == [
        "0/validated_traffic.csv",
        "2/validated_traffic.csv",
    ]
    assert staged[0].read_bytes() == a.read_bytes()


def test_the_snapshot_does_not_change_when_the_live_store_grows(tmp_path):
    live = _csv(tmp_path / "validated_traffic.csv", ["BENIGN"])
    artifacts = tmp_path / "artifacts"
    stage_feedback_snapshot([live], tmp_path / "stage")
    install_feedback_snapshot(tmp_path / "stage", artifacts)

    _csv(live, ["BENIGN", "Bot"])  # an analyst submits more feedback after training

    files = training_feedback_csvs(artifacts, _preprocessing([str(live)]))
    assert len(files) == 1 and Path(files[0]).parent.parent.name == SNAPSHOT_DIRNAME
    assert pd.read_csv(files[0])["Label"].tolist() == ["BENIGN"]


def test_a_run_without_feedback_replaces_an_older_snapshot_with_an_empty_one(tmp_path):
    artifacts = tmp_path / "artifacts"
    _csv(artifacts / SNAPSHOT_DIRNAME / "0" / "validated_traffic.csv", ["BENIGN"])  # from a previous run

    install_feedback_snapshot(tmp_path / "never-created", artifacts)

    assert (artifacts / SNAPSHOT_DIRNAME).is_dir()
    assert training_feedback_csvs(artifacts, _preprocessing(["/somewhere/validated_traffic.csv"])) == []


def test_slots_are_read_in_numeric_order(tmp_path):
    artifacts = tmp_path / "artifacts"
    for slot in (10, 2):
        _csv(artifacts / SNAPSHOT_DIRNAME / str(slot) / f"f{slot}.csv", ["BENIGN"])
    assert [Path(p).name for p in training_feedback_csvs(artifacts, _preprocessing([]))] == ["f2.csv", "f10.csv"]


def test_models_from_before_snapshots_fall_back_to_their_recorded_paths(tmp_path):
    assert training_feedback_csvs(tmp_path, _preprocessing(["a.csv", "b.csv"])) == ["a.csv", "b.csv"]


def test_the_held_out_rebuild_loads_the_snapshot(tmp_path, monkeypatch):
    """cyber_ai.holdout feeds the snapshot -- not the live store -- to the data loader."""
    artifacts = tmp_path / "artifacts"
    _csv(artifacts / SNAPSHOT_DIRNAME / "0" / "validated_traffic.csv", ["BENIGN"])
    preprocessing = {
        "config": {"data": {"feedback_csvs": ["/live/validated_traffic.csv"], "data_dir": "x", "random_state": 42}},
        "window_size": 10,
        "stride": 5,
        "feature_names": [],
    }
    seen = {}

    class Stop(Exception):
        pass

    def fake_load(data_dir, feedback_csvs, random_state):
        seen["feedback_csvs"] = list(feedback_csvs)
        raise Stop

    monkeypatch.setattr(holdout.joblib, "load", lambda _path: preprocessing)
    monkeypatch.setattr(holdout, "load_cicids2017", fake_load)
    try:
        holdout.build_holdout(artifacts)
    except Stop:
        pass
    assert seen["feedback_csvs"] == [str(artifacts / SNAPSHOT_DIRNAME / "0" / "validated_traffic.csv")]
