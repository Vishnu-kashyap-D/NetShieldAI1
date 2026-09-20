"""Rebuild the exact validation / test windows the deployed model was trained against.

`cyber_ai.train` does not save per-window predictions, only summary metrics. The research scripts
(calibration, abstention, adversarial robustness, drift reference) need the *windows themselves*, so
this recreates them the way `train.py` does -- same data files, same feature set, same seeded window
sampling and split -- using the configuration stored inside `artifacts/preprocessing.joblib`.

`verify_against_metrics` proves the reconstruction is faithful by comparing window counts with what the
trainer recorded in `reports/training_metrics.json`; every script calls it and refuses to continue on a
mismatch, so a result is never computed on a split that isn't the model's real held-out set.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from cyber_ai.data import (
    SOURCE_COLUMN,
    build_window_starts_grouped,
    dataframe_to_features,
    load_cicids2017,
    map_labels_to_attack_categories,
    sample_window_starts_by_class,
    split_window_starts,
    window_labels,
)
from cyber_ai.modeling import classifier_probabilities, reconstruction_errors
from cyber_ai.windowing import WindowSequence


@dataclass
class Holdout:
    X: np.ndarray                      # every row, imputed + scaled, float32
    y_raw: np.ndarray                  # raw-label id per row (BENIGN, DDoS, ...)
    y_category: np.ndarray             # attack-category id per row, -1 for BENIGN / unmapped
    benign_id: int
    window_size: int
    stride: int
    category_names: list[str]
    feature_names: list[str]
    validation_starts: np.ndarray
    test_starts: np.ndarray
    preprocessing: dict
    X_raw: np.ndarray | None = None    # same rows before imputing/scaling (NaN where missing), float32

    def is_attack(self, starts: np.ndarray) -> np.ndarray:
        """True where the window's last row is anything other than BENIGN (the trainer's binary target)."""
        return window_labels(self.y_raw, starts, self.window_size) != self.benign_id

    def category_of(self, starts: np.ndarray) -> np.ndarray:
        """Attack-category id of each window's last row (-1 = benign / unmapped)."""
        return window_labels(self.y_category, starts, self.window_size)


def build_holdout(artifacts_dir: Path, data_dir: Path | None = None) -> Holdout:
    preprocessing = joblib.load(Path(artifacts_dir) / "preprocessing.joblib")
    config = preprocessing["config"]
    data_config = config["data"]
    window_size = int(preprocessing["window_size"])
    stride = int(preprocessing["stride"])
    random_state = int(data_config["random_state"])
    feature_names = list(preprocessing["feature_names"])

    df = load_cicids2017(
        data_dir=data_dir or data_config["data_dir"],
        feedback_csvs=data_config.get("feedback_csvs") or [],
        random_state=random_state,
    )
    X_raw, raw_labels, _ = dataframe_to_features(df, feature_names=feature_names)
    y_raw = preprocessing["raw_label_encoder"].transform(raw_labels)

    attack_categories = map_labels_to_attack_categories(raw_labels)
    attack_mask = np.array([category is not None for category in attack_categories], dtype=bool)
    y_category = np.full(len(raw_labels), -1, dtype=np.int64)
    y_category[attack_mask] = preprocessing["label_encoder"].transform(attack_categories[attack_mask])

    starts = build_window_starts_grouped(df[SOURCE_COLUMN].to_numpy(), window_size, stride)
    cap = data_config.get("max_rows_per_class")
    max_rows = data_config.get("max_rows")
    if cap is not None:
        starts = sample_window_starts_by_class(starts, window_labels(y_raw, starts, window_size), int(cap), random_state)
    elif max_rows is not None and len(starts) > max_rows:
        rng = np.random.RandomState(random_state)
        starts = np.sort(rng.choice(starts, size=int(max_rows), replace=False))

    _, validation_starts, test_starts = split_window_starts(
        starts=starts,
        y=y_raw,
        window_size=window_size,
        validation_size=float(config["preprocessing"]["validation_size"]),
        test_size=float(config["preprocessing"]["test_size"]),
        random_state=random_state,
    )

    X = preprocessing["scaler"].transform(preprocessing["imputer"].transform(X_raw)).astype(np.float32)
    return Holdout(
        X=X, y_raw=y_raw, y_category=y_category, benign_id=int(preprocessing["benign_id"]),
        window_size=window_size, stride=stride, category_names=list(preprocessing["class_names"]),
        feature_names=feature_names, validation_starts=validation_starts, test_starts=test_starts,
        preprocessing=preprocessing, X_raw=X_raw.to_numpy(dtype=np.float32),
    )


def verify_against_metrics(holdout: Holdout, metrics_path: Path) -> None:
    """Refuse to continue unless the rebuilt split matches what the trainer recorded."""
    recorded = json.loads(Path(metrics_path).read_text(encoding="utf-8"))["data"]["windows"]
    rebuilt = {
        "validation": int(len(holdout.validation_starts)),
        "test": int(len(holdout.test_starts)),
        "classifier_test_attack": int((holdout.category_of(holdout.test_starts) >= 0).sum()),
    }
    mismatches = {key: (rebuilt[key], recorded[key]) for key in rebuilt if rebuilt[key] != recorded[key]}
    if mismatches:
        raise RuntimeError(
            "The rebuilt held-out split does not match reports/training_metrics.json "
            f"(rebuilt, recorded): {mismatches}. The data files or the artifacts differ from what was "
            "trained, so results computed on this split would not describe the deployed model."
        )


def load_models(artifacts_dir: Path):
    import tensorflow as tf

    models_dir = Path(artifacts_dir) / "models"
    return (
        tf.keras.models.load_model(models_dir / "autoencoder.keras"),
        tf.keras.models.load_model(models_dir / "bilstm_classifier.keras"),
    )


def autoencoder_errors(autoencoder, X: np.ndarray, starts: np.ndarray, window_size: int) -> np.ndarray:
    sequence = WindowSequence(X, starts=starts, window_size=window_size, batch_size=512, target_mode="autoencoder", shuffle=False)
    return reconstruction_errors(autoencoder, sequence)


def classifier_probs(classifier, X: np.ndarray, starts: np.ndarray, window_size: int) -> np.ndarray:
    if len(starts) == 0:
        return np.empty((0, 0))
    sequence = WindowSequence(X, starts=starts, window_size=window_size, batch_size=512, target_mode=None, shuffle=False)
    return classifier_probabilities(classifier, sequence)


# ---------------------------------------------------------------------------------------------------
# Cached per-window scores: rebuilding the split loads ~2.8M rows (minutes), so every research script
# shares one cache instead of repeating that.
# ---------------------------------------------------------------------------------------------------


@dataclass
class HoldoutScores:
    """Deployed-model outputs for every validation and test window (all windows, not just flagged ones)."""

    validation_errors: np.ndarray       # Autoencoder reconstruction error per window
    validation_probs: np.ndarray        # BiLSTM class probabilities per window (run on ALL windows, for analysis)
    validation_is_attack: np.ndarray    # bool: last row is not BENIGN
    validation_category: np.ndarray     # attack-category id, -1 = benign / unmapped
    validation_label: np.ndarray        # raw label id
    test_errors: np.ndarray
    test_probs: np.ndarray
    test_is_attack: np.ndarray
    test_category: np.ndarray
    test_label: np.ndarray
    test_raw_windows: np.ndarray        # (n, window, features) unscaled feature values of each test window
    raw_class_names: list[str]
    category_names: list[str]
    feature_names: list[str]
    window_size: int
    stride: int


_CACHE_KEYS = [
    "validation_errors", "validation_probs", "validation_is_attack", "validation_category", "validation_label",
    "test_errors", "test_probs", "test_is_attack", "test_category", "test_label", "test_raw_windows",
]


def _artifact_fingerprint(artifacts_dir: Path) -> str:
    parts = []
    for relative in ["preprocessing.joblib", "models/autoencoder.keras", "models/bilstm_classifier.keras"]:
        stat = (Path(artifacts_dir) / relative).stat()
        parts.append(f"{relative}:{stat.st_size}:{stat.st_mtime_ns}")
    return "|".join(parts)


def load_scores(artifacts_dir: Path, metrics_path: Path, cache_path: Path, data_dir: Path | None = None,
                rebuild: bool = False) -> HoldoutScores:
    """Return the deployed model's per-window outputs on the held-out windows, from cache when valid."""
    artifacts_dir = Path(artifacts_dir)
    fingerprint = _artifact_fingerprint(artifacts_dir)
    preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")

    if not rebuild and Path(cache_path).exists():
        with np.load(cache_path, allow_pickle=False) as cached:
            if str(cached["fingerprint"]) == fingerprint:
                return HoldoutScores(
                    **{key: cached[key] for key in _CACHE_KEYS},
                    raw_class_names=list(preprocessing["raw_class_names"]),
                    category_names=list(preprocessing["class_names"]),
                    feature_names=list(preprocessing["feature_names"]),
                    window_size=int(preprocessing["window_size"]),
                    stride=int(preprocessing["stride"]),
                )

    print("Rebuilding the held-out split (loads the full dataset; takes a few minutes)...")
    holdout = build_holdout(artifacts_dir, data_dir)
    verify_against_metrics(holdout, metrics_path)
    autoencoder, classifier = load_models(artifacts_dir)
    window = holdout.window_size

    def score(starts: np.ndarray) -> dict[str, np.ndarray]:
        return {
            "errors": autoencoder_errors(autoencoder, holdout.X, starts, window),
            "probs": classifier_probs(classifier, holdout.X, starts, window),
            "is_attack": holdout.is_attack(starts),
            "category": holdout.category_of(starts),
            "label": window_labels(holdout.y_raw, starts, window),
        }

    validation, test = score(holdout.validation_starts), score(holdout.test_starts)
    offsets = np.arange(window)
    raw_windows = holdout.X_raw[holdout.test_starts[:, None] + offsets[None, :]]  # (n, window, features)

    arrays = {f"validation_{key}": value for key, value in validation.items()}
    arrays.update({f"test_{key}": value for key, value in test.items()})
    arrays["test_raw_windows"] = raw_windows
    Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(cache_path, fingerprint=np.array(fingerprint), **arrays)
    return HoldoutScores(
        **{key: arrays[key] for key in _CACHE_KEYS},
        raw_class_names=list(preprocessing["raw_class_names"]),
        category_names=holdout.category_names,
        feature_names=holdout.feature_names,
        window_size=window,
        stride=holdout.stride,
    )
