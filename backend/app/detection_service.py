from __future__ import annotations

import logging
import uuid
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from app.config import settings
from app.engine_cache import ReloadableCache
from app.feature_schema import feature_schema_version
from cyber_ai.data import (
    ATTACK_CATEGORIES,
    BENIGN_LABEL,
    NORMAL_DECISION_LABEL,
    RAW_LABEL_TO_ATTACK_CATEGORY,
    SOURCE_COLUMN,
    build_window_starts_grouped,
    clean_raw_dataframe,
    dataframe_to_features,
    normalize_label,
    to_attack_category,
)
from cyber_ai.correlation import find_campaigns
from cyber_ai.drift import bin_scores, load_reference, reference_id
from cyber_ai.explain import explain_autoencoder_windows, explain_classifier_windows
from cyber_ai.hybrid_risk import apply_abstention, compute_risk_score, normalize_anomaly_score, risk_levels_for
from cyber_ai.modeling import classifier_probabilities, reconstruction_errors
from cyber_ai.windowing import WindowSequence

logger = logging.getLogger("netshield.backend")

# The ingested CSV's "Label" column is ground truth the *uploader* supplies -- untrusted text --
# and Alert.actual_label is later pasted into the per-alert chatbot's LLM prompt (chat_service.
# build_alert_context). Anything outside the label vocabulary this project actually knows
# (CICIDS2017's raw labels, the project's attack categories, benign/normal) is stored as a fixed
# placeholder instead of verbatim, so a crafted CSV can't smuggle arbitrary text into that prompt.
_KNOWN_GROUND_TRUTH_LABELS = frozenset(
    {BENIGN_LABEL, NORMAL_DECISION_LABEL, "Normal / Ignored", *ATTACK_CATEGORIES, *RAW_LABEL_TO_ATTACK_CATEGORY}
)
UNRECOGNIZED_LABEL = "Unrecognized"


def _storable_ground_truth_label(label: str) -> str | None:
    """None for "no label supplied"; the label itself if it's a known one; else UNRECOGNIZED_LABEL."""
    if not label:
        return None
    return label if label in _KNOWN_GROUND_TRUTH_LABELS else UNRECOGNIZED_LABEL


class DetectionEngine:
    """Loads the trained pipeline once and scores traffic dataframes on demand.

    This mirrors cyber_ai.predict's logic exactly (same functions, same order of
    operations) so API-served alerts are identical to what the CLI would produce for
    the same input -- it's a reusable version of that script, not a reimplementation.
    """

    def __init__(
        self,
        artifacts_dir: Path,
        unknown_confidence_threshold: float | None = None,
        campaign_params: dict | None = None,
    ):
        # Cross-window campaign detection settings (min_confidence / min_windows / max_gap); None = off.
        self.campaign_params = campaign_params
        # Below this classifier confidence a flagged window is labelled "Unknown" rather than forced into one of
        # the six known categories (cyber_ai.hybrid_risk.apply_abstention). None / 0 = never abstain.
        self.unknown_confidence_threshold = unknown_confidence_threshold
        preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")
        self.feature_names: list[str] = preprocessing["feature_names"]
        self.feature_schema_version: str = feature_schema_version(self.feature_names)
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

        # Bins for drift monitoring (cyber_ai/drift.py). Optional: absent for artifacts trained before this
        # existed, and ignored if it was built for a different anomaly threshold (i.e. a different model).
        reference = load_reference(artifacts_dir)
        if reference is not None and abs(reference["anomaly_threshold"] - self.anomaly_threshold) > 1e-9:
            reference = None
        self.drift_reference = reference

        self.autoencoder = tf.keras.models.load_model(artifacts_dir / "models" / "autoencoder.keras")
        self.classifier = tf.keras.models.load_model(artifacts_dir / "models" / "bilstm_classifier.keras")

    @staticmethod
    def _choose_background_starts(starts: np.ndarray, max_background: int) -> np.ndarray:
        if len(starts) <= max_background:
            return starts
        positions = np.linspace(0, len(starts) - 1, max_background, dtype=np.int64)
        return starts[positions]

    def _detect_campaigns(
        self,
        window_sources: np.ndarray,
        starts: np.ndarray,
        classes: np.ndarray,
        confidences: np.ndarray,
        risk_scores: np.ndarray,
    ) -> list[dict]:
        """Long runs of consecutive windows the classifier keeps reading as one category at very high confidence,
        whether or not the anomaly gate flagged them (see cyber_ai/correlation.py). Each capture file is its own
        stream: a run never bridges two files."""
        found: list[dict] = []
        for source in dict.fromkeys(window_sources.tolist()):  # distinct sources, in order of appearance
            mask = window_sources == source
            for campaign in find_campaigns(
                starts[mask], classes[mask], confidences[mask], risk_scores[mask],
                self.risk_low_threshold, self.window_size, self.stride, **self.campaign_params,
            ):
                found.append({
                    "source_file": str(source),
                    "category": normalize_label(self.label_encoder.inverse_transform([campaign.category])[0]),
                    "first_window": campaign.first_window,
                    "last_window": campaign.last_window,
                    "windows": campaign.windows,
                    "alerted_windows": campaign.alerted_windows,
                    "mean_confidence": campaign.mean_confidence,
                })
        return found

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

        predicted_labels, abstained = apply_abstention(
            predicted_labels, confidences, is_anomaly, self.unknown_confidence_threshold
        )

        score_distribution = None
        if self.drift_reference is not None:
            score_distribution = {**bin_scores(anomaly_scores, self.drift_reference), "reference_id": reference_id(self.drift_reference)}

        normalized_anomaly_scores = normalize_anomaly_score(
            anomaly_scores, self.anomaly_score_low, self.anomaly_score_high
        )
        risk_scores = compute_risk_score(normalized_anomaly_scores, classifier_confidence_for_risk)
        risk_levels = risk_levels_for(risk_scores, self.risk_low_threshold, self.risk_high_threshold)

        campaigns: list[dict] = []
        if self.campaign_params:
            # The classifier normally only ever sees the windows the anomaly gate flagged; persistence detection
            # needs its opinion on every window, because the gate misses whole attacks (most Port Scanning).
            every_window = classifier_probabilities(
                self.classifier,
                WindowSequence(X, starts=starts, window_size=self.window_size, batch_size=1024, target_mode=None, shuffle=False),
            )  # batch 1024: measured ~1.8x faster than 256 here, bit-identical output
            campaigns = self._detect_campaigns(
                df[SOURCE_COLUMN].to_numpy()[starts], starts, every_window.argmax(axis=1), every_window.max(axis=1), risk_scores
            )

        keep_mask = np.ones(len(starts), dtype=bool) if include_all_windows else (risk_levels != "Low")
        kept_positions = np.where(keep_mask)[0]

        classifier_explanations: dict[int, str] = {}
        anomaly_explanations: dict[int, str] = {}
        if shap and len(classifier_starts) > 0:
            explain_starts = classifier_starts[:shap_max_alerts]
            background_starts = self._choose_background_starts(starts, shap_background)
            # Each explainer runs independently and is never allowed to fail the whole batch --
            # a GradientExplainer error (numerical issue, shap-library version mismatch, etc.)
            # degrades that one explanation to "unavailable" instead of losing every alert in
            # this ingest call, which is the real prediction/risk output and must not be lost
            # over an explainability failure.
            try:
                classifier_explanations = explain_classifier_windows(
                    self.classifier, X, explain_starts, background_starts,
                    self.window_size, self.feature_names, nsamples=shap_samples,
                )
            except Exception:
                logger.exception("SHAP classifier explanation failed; continuing without it.")
            try:
                anomaly_explanations = explain_autoencoder_windows(
                    self.autoencoder, X, explain_starts, background_starts,
                    self.window_size, self.feature_names, nsamples=shap_samples,
                )
            except Exception:
                logger.exception("SHAP anomaly explanation failed; continuing without it.")

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
                    "actual_label": _storable_ground_truth_label(actual_label),
                    "actual_category": actual_category,
                    "predicted_label": predicted_label,
                    "confidence": float(confidences[position]),
                    "anomaly_score": float(anomaly_scores[position]),
                    "anomaly_threshold": self.anomaly_threshold,
                    "is_anomaly": bool(is_anomaly[position]),
                    "pipeline_action": _pipeline_action(bool(is_anomaly[position]), bool(abstained[position])),
                    "risk_score": float(risk_scores[position]),
                    "risk_level": str(risk_levels[position]),
                    "top_classifier_features": classifier_explanations.get(start, "") or None,
                    "top_anomaly_features": anomaly_explanations.get(start, "") or None,
                    "features": {
                        feature: _json_safe(source_row.get(feature, np.nan)) for feature in self.feature_names
                    },
                    "feature_schema_version": self.feature_schema_version,
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
            # Not part of the API response: ingest stores it as a ScoreBatch row (see routers/ingest.py).
            "score_distribution": score_distribution,
            # Not part of the API response either: stored as CorrelatedCampaign rows by routers/ingest.py.
            "campaigns": campaigns,
        }
        return records, summary


def _campaign_params() -> dict | None:
    if not settings.campaign_detection_enabled:
        return None
    return {
        "min_confidence": settings.campaign_min_confidence,
        "min_windows": settings.campaign_min_windows,
        "max_gap": settings.campaign_max_gap,
    }


def _pipeline_action(is_anomaly: bool, abstained: bool) -> str:
    if not is_anomaly:
        return "Ignored as normal"
    return "Flagged as anomalous, category unknown" if abstained else "Classified and alerted"


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


# Per-process cache whose invalidation is shared across worker processes through a marker file
# (see app.engine_cache) -- so a retrain accepted on one `uvicorn` worker reloads all of them.
_engine_cache: ReloadableCache[DetectionEngine] = ReloadableCache(
    loader=lambda: DetectionEngine(settings.artifacts_dir, settings.unknown_confidence_threshold, _campaign_params()),
    marker_path=lambda: settings.model_generation_file,
)


def get_engine() -> DetectionEngine:
    return _engine_cache.get()


def reload_engine() -> None:
    """Make every worker reload the model from artifacts/ on its next get_engine().

    Call this only once the new weights are final and approved (the retrain quality gate does).
    """
    _engine_cache.invalidate()
