from __future__ import annotations

import uuid
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from app.config import settings
from cyber_ai.data import (
    NORMAL_DECISION_LABEL,
    SOURCE_COLUMN,
    build_window_starts_grouped,
    clean_raw_dataframe,
    dataframe_to_features,
    normalize_label,
    to_attack_category,
)
from cyber_ai.explain import explain_autoencoder_windows, explain_classifier_windows
from cyber_ai.hybrid_risk import compute_risk_score, normalize_anomaly_score, risk_levels_for
from cyber_ai.modeling import classifier_probabilities, reconstruction_errors
from cyber_ai.windowing import WindowSequence


class DetectionEngine:
    """Loads the trained pipeline once and scores traffic dataframes on demand.

    This mirrors cyber_ai.predict's logic exactly (same functions, same order of
    operations) so API-served alerts are identical to what the CLI would produce for
    the same input -- it's a reusable version of that script, not a reimplementation.
    """

    def __init__(self, artifacts_dir: Path):
        preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")
        self.feature_names: list[str] = preprocessing["feature_names"]
        self.imputer = preprocessing["imputer"]
        self.scaler = preprocessing["scaler"]
        self.label_encoder = preprocessing["label_encoder"]
        self.window_size = int(preprocessing["window_size"])
        self.stride = int(preprocessing["stride"])
        self.anomaly_threshold = float(preprocessing["anomaly_threshold"])
        self.anomaly_score_low = float(preprocessing["anomaly_score_low"])
        self.anomaly_score_high = float(preprocessing["anomaly_score_high"])
        self.risk_low_threshold = float(preprocessing["risk_low_threshold"])
        self.risk_high_threshold = float(preprocessing["risk_high_threshold"])

        self.autoencoder = tf.keras.models.load_model(artifacts_dir / "models" / "autoencoder.keras")
        self.classifier = tf.keras.models.load_model(artifacts_dir / "models" / "bilstm_classifier.keras")

    @staticmethod
    def _choose_background_starts(starts: np.ndarray, max_background: int) -> np.ndarray:
        if len(starts) <= max_background:
            return starts
        positions = np.linspace(0, len(starts) - 1, max_background, dtype=np.int64)
        return starts[positions]

    def score_dataframe(
        self,
        df: pd.DataFrame,
        include_all_windows: bool = False,
        shap: bool = False,
        shap_background: int = 20,
        shap_samples: int = 100,
        shap_max_alerts: int = 20,
    ) -> tuple[list[dict], dict]:
        X_raw, raw_labels, _ = dataframe_to_features(df, feature_names=self.feature_names)
        X = self.scaler.transform(self.imputer.transform(X_raw)).astype(np.float32)

        starts = build_window_starts_grouped(df[SOURCE_COLUMN].to_numpy(), self.window_size, self.stride)
        if len(starts) == 0:
            raise ValueError("No windows were created. Check input size, window size, and stride.")

        ae_sequence = WindowSequence(
            X, starts=starts, window_size=self.window_size, batch_size=256,
            target_mode="autoencoder", shuffle=False,
        )
        anomaly_scores = reconstruction_errors(self.autoencoder, ae_sequence)
        is_anomaly = anomaly_scores > self.anomaly_threshold
        classifier_positions = np.where(is_anomaly)[0]
        classifier_starts = starts[classifier_positions]

        predicted_labels = np.full(len(starts), NORMAL_DECISION_LABEL, dtype=object)
        confidences = np.zeros(len(starts), dtype=np.float32)
        classifier_confidence_for_risk = np.full(len(starts), np.nan, dtype=np.float64)
        if len(classifier_starts) > 0:
            prediction_sequence = WindowSequence(
                X, starts=classifier_starts, window_size=self.window_size, batch_size=256,
                target_mode=None, shuffle=False,
            )
            probabilities = classifier_probabilities(self.classifier, prediction_sequence)
            predicted_ids = probabilities.argmax(axis=1)
            predicted_labels[classifier_positions] = self.label_encoder.inverse_transform(predicted_ids)
            max_probabilities = probabilities.max(axis=1)
            confidences[classifier_positions] = max_probabilities
            classifier_confidence_for_risk[classifier_positions] = max_probabilities

        normalized_anomaly_scores = normalize_anomaly_score(
            anomaly_scores, self.anomaly_score_low, self.anomaly_score_high
        )
        risk_scores = compute_risk_score(normalized_anomaly_scores, classifier_confidence_for_risk)
        risk_levels = risk_levels_for(risk_scores, self.risk_low_threshold, self.risk_high_threshold)

        keep_mask = np.ones(len(starts), dtype=bool) if include_all_windows else (risk_levels != "Low")
        kept_positions = np.where(keep_mask)[0]

        classifier_explanations: dict[int, str] = {}
        anomaly_explanations: dict[int, str] = {}
        if shap and len(classifier_starts) > 0:
            explain_starts = classifier_starts[:shap_max_alerts]
            background_starts = self._choose_background_starts(starts, shap_background)
            classifier_explanations = explain_classifier_windows(
                self.classifier, X, explain_starts, background_starts,
                self.window_size, self.feature_names, nsamples=shap_samples,
            )
            anomaly_explanations = explain_autoencoder_windows(
                self.autoencoder, X, explain_starts, background_starts,
                self.window_size, self.feature_names, nsamples=shap_samples,
            )

        records: list[dict] = []
        for position in kept_positions:
            start = int(starts[position])
            end = start + self.window_size - 1
            source_row = df.iloc[end]
            predicted_label = normalize_label(predicted_labels[position])
            actual_label = normalize_label(raw_labels[end]) if raw_labels is not None else ""
            actual_category = to_attack_category(actual_label) or NORMAL_DECISION_LABEL
            records.append(
                {
                    "window_start": start,
                    "window_end": end,
                    "source_file": str(source_row.get(SOURCE_COLUMN, "")),
                    "actual_label": actual_label or None,
                    "actual_category": actual_category,
                    "predicted_label": predicted_label,
                    "confidence": float(confidences[position]),
                    "anomaly_score": float(anomaly_scores[position]),
                    "anomaly_threshold": self.anomaly_threshold,
                    "is_anomaly": bool(is_anomaly[position]),
                    "pipeline_action": "Classified and alerted" if is_anomaly[position] else "Ignored as normal",
                    "risk_score": float(risk_scores[position]),
                    "risk_level": str(risk_levels[position]),
                    "top_classifier_features": classifier_explanations.get(start, "") or None,
                    "top_anomaly_features": anomaly_explanations.get(start, "") or None,
                    "features": {
                        feature: _json_safe(source_row.get(feature, np.nan)) for feature in self.feature_names
                    },
                }
            )

        summary = {
            "windows_scored": int(len(starts)),
            "anomalous_windows": int(is_anomaly.sum()),
            "alerts_written": int(len(records)),
            "risk_level_counts": {
                str(level): int(count) for level, count in pd.Series(risk_levels).value_counts().items()
            },
            "predicted_label_counts": {
                str(label): int(count) for label, count in pd.Series(predicted_labels).value_counts().items()
            },
        }
        return records, summary


def _json_safe(value: object) -> object:
    if isinstance(value, (np.floating,)):
        value = float(value)
        return None if np.isnan(value) else value
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, float) and np.isnan(value):
        return None
    return value


def load_csv_as_traffic_frame(path_or_buffer, source_name: str) -> pd.DataFrame:
    frame = pd.read_csv(path_or_buffer, low_memory=False)
    return clean_raw_dataframe(frame, source_name=source_name)


def new_batch_id() -> str:
    return str(uuid.uuid4())


_engine: DetectionEngine | None = None


def get_engine() -> DetectionEngine:
    global _engine
    if _engine is None:
        _engine = DetectionEngine(settings.artifacts_dir)
    return _engine


def reload_engine() -> None:
    """Drop the cached engine so the next get_engine() picks up freshly retrained weights."""
    global _engine
    _engine = None
