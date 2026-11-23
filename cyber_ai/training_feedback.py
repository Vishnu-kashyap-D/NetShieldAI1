"""Freezing the exact analyst-feedback rows a model was trained on, next to the model itself.

The feedback store (data/feedback/validated_traffic.csv) is append-only: every analyst correction after
a training run adds a row to it. Training only recorded that file's *path*, so anything that later had to
rebuild the model's exact train/validation/test split (cyber_ai.holdout, cyber_ai.calibrate,
cyber_ai.report_assets) re-read the file as it was *now* -- one new feedback row shifted the windows,
and the held-out split no longer matched the model. The path was also absolute (``V:\\...``), so the
same rebuild silently dropped the feedback on any other machine or in Docker.

So train.py copies each feedback CSV it uses, before loading it, and installs the copies in
``<artifacts>/training_feedback/<n>/<original file name>`` once training succeeds. The original file
name is kept because it becomes the rows' ``source_file``, which decides where windows may start. The
snapshot travels with the artifacts (backups, Docker image, git) and never changes after training.
"""
from __future__ import annotations

import shutil
from collections.abc import Iterable
from pathlib import Path

SNAPSHOT_DIRNAME = "training_feedback"


def stage_feedback_snapshot(feedback_csvs: Iterable[str | Path], staging_dir: Path) -> list[Path]:
    """Copies each existing feedback CSV to ``staging_dir/<n>/<name>`` and returns the copies, in order.

    Training then loads the copies, so rows an analyst appends while a (minutes-long) training run is in
    progress can't end up half in the model and missing from the snapshot. Missing files are skipped,
    exactly as ``load_cicids2017`` skips them.
    """
    staged: list[Path] = []
    for index, source in enumerate(feedback_csvs):
        source = Path(source)
        if not source.exists():
            continue
        target = Path(staging_dir) / str(index) / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        staged.append(target)
    return staged


def install_feedback_snapshot(staging_dir: Path, artifacts_dir: Path) -> None:
    """Replaces ``<artifacts>/training_feedback`` with the staged copies (an empty folder when none).

    Always written, even without feedback: the folder's presence is what tells readers that this model's
    feedback is recorded here rather than only as a path in its config.
    """
    destination = Path(artifacts_dir) / SNAPSHOT_DIRNAME
    if destination.exists():
        shutil.rmtree(destination)
    if Path(staging_dir).exists():
        shutil.copytree(staging_dir, destination)
    else:
        destination.mkdir(parents=True)


def training_feedback_csvs(artifacts_dir: Path, preprocessing: dict) -> list[str]:
    """The feedback CSVs to load when rebuilding this model's training data.

    Uses the snapshot when the artifacts have one. Models trained before snapshots existed fall back to
    the paths recorded in their config -- which only reproduce the split if those files are unchanged.
    """
    snapshot = Path(artifacts_dir) / SNAPSHOT_DIRNAME
    if snapshot.is_dir():
        slots = sorted((p for p in snapshot.iterdir() if p.is_dir() and p.name.isdigit()), key=lambda p: int(p.name))
        return [str(csv) for slot in slots for csv in sorted(slot.glob("*.csv"))]
    return list(preprocessing["config"]["data"].get("feedback_csvs") or [])
