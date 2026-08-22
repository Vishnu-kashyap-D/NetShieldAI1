from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer


def rank_feature_importance(
    X_raw: pd.DataFrame,
    row_labels: np.ndarray,
    feature_names: list[str],
    random_state: int = 42,
    max_rows: int = 150_000,
    n_estimators: int = 200,
) -> list[tuple[str, float]]:
    """Rank features by Random Forest importance for BENIGN-vs-attack-category discrimination.

    This is a lightweight, row-level pass used only to decide which of the sequence models'
    input columns are worth keeping — it is not itself a detector, and its output should never
    be trained/evaluated on anything but the caller's training rows (avoid leaking val/test).
    """
    if len(X_raw) > max_rows:
        rng = np.random.RandomState(random_state)
        sample_positions = rng.choice(len(X_raw), size=max_rows, replace=False)
        X_sample = X_raw.iloc[sample_positions]
        y_sample = row_labels[sample_positions]
    else:
        X_sample = X_raw
        y_sample = row_labels

    imputer = SimpleImputer(strategy="median")
    X_imputed = imputer.fit_transform(X_sample)

    forest = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=20,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    forest.fit(X_imputed, y_sample)

    ranked = sorted(
        zip(feature_names, forest.feature_importances_),
        key=lambda item: item[1],
        reverse=True,
    )
    return [(name, float(importance)) for name, importance in ranked]


def select_top_k_features(ranked: list[tuple[str, float]], top_k: int) -> list[str]:
    return [name for name, _ in ranked[:top_k]]
