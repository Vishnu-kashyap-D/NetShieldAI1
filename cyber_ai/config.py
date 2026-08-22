from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG: dict[str, Any] = {
    "data": {
        "data_dir": "MachineLearningCVE",
        "feedback_csvs": [],
        "max_rows": None,
        "max_rows_per_class": 50000,
        "random_state": 42,
    },
    "preprocessing": {
        "window_size": 10,
        "stride": 5,
        "validation_size": 0.15,
        "test_size": 0.15,
        "top_k_features": None,
    },
    "training": {
        "batch_size": 256,
        "autoencoder_epochs": 12,
        "classifier_epochs": 12,
        "learning_rate": 0.001,
        "early_stopping_patience": 3,
    },
    "models": {
        "latent_dim": 32,
        "autoencoder_units": 64,
        "classifier_units": 64,
        "dropout": 0.25,
    },
    "anomaly": {
        "threshold_strategy": "balanced_accuracy",
        "threshold_quantile": 0.995,
    },
    "paths": {
        "artifacts_dir": "artifacts",
        "reports_dir": "reports",
    },
}


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    config = deepcopy(DEFAULT_CONFIG)
    if path is None:
        return config

    config_path = Path(path)
    if not config_path.exists():
        return config

    with config_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    return deep_merge(config, loaded)
