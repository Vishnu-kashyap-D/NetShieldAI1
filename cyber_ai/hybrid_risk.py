from __future__ import annotations

import numpy as np


def normalize_anomaly_score(raw_error: np.ndarray | float, low: float, high: float) -> np.ndarray:
    """Scale raw Autoencoder reconstruction error into a [0, 1] "how anomalous" signal.

    `low`/`high` are calibrated once from the validation error distribution (see
    `calibrate_anomaly_score_range`) rather than the batch's own min/max, so the scale is
    stable across different inference calls instead of drifting with whatever happens to be
    in the current batch.
    """
    raw_error = np.asarray(raw_error, dtype=np.float64)
    if high <= low:
        return np.zeros_like(raw_error)
    return np.clip((raw_error - low) / (high - low), 0.0, 1.0)


def calibrate_anomaly_score_range(
    validation_errors: np.ndarray,
    low_quantile: float = 0.05,
    high_quantile: float = 0.95,
) -> tuple[float, float]:
    """Pick stable low/high anchors for anomaly-score normalization from validation errors.

    Percentiles rather than raw min/max, so a single extreme outlier in validation can't
    compress every other score toward 0.
    """
    validation_errors = np.asarray(validation_errors, dtype=np.float64)
    low = float(np.quantile(validation_errors, low_quantile))
    high = float(np.quantile(validation_errors, high_quantile))
    if high <= low:
        high = low + 1e-9
    return low, high


def compute_risk_score(anomaly_score: np.ndarray | float, class_probability: np.ndarray | float | None) -> np.ndarray:
    """Fuse the Autoencoder's anomaly signal with BiLSTM's classification confidence.

    Sequential-gate design (Autoencoder decides whether BiLSTM even runs): a window that
    never reached the classifier only has an anomaly score to go on. A window BiLSTM did
    classify can only have its risk pulled UP toward classifier confidence, never down below
    what the anomaly detector alone already thought — a confident attack classification
    should never be reported as less risky than the anomaly gate that let it through.

    `class_probability` is None when no window in the batch was classified, or an array the
    same shape as `anomaly_score` containing NaN for any window that wasn't (that's how a
    mixed batch — some flagged, some not — gets scored in one call).
    """
    anomaly_score = np.asarray(anomaly_score, dtype=np.float64)
    if class_probability is None:
        return anomaly_score

    class_probability = np.asarray(class_probability, dtype=np.float64)
    classified = ~np.isnan(class_probability)
    risk = anomaly_score.copy()
    risk[classified] = np.maximum(risk[classified], class_probability[classified])
    return risk


def calibrate_risk_levels(
    risk_scores: np.ndarray,
    is_true_attack: np.ndarray,
    benign_quantile: float = 0.90,
    attack_quantile: float = 0.50,
) -> tuple[float, float]:
    """Pick Low/Medium and Medium/High risk-score boundaries from validation data.

    Low/Medium boundary: the risk score below which most known-BENIGN validation windows
    fall (so "Low" means "scores like traffic we've confirmed is normal").
    Medium/High boundary: the risk score at or above which the *typical* known-attack
    validation window scores (so "High" means "at least as suspicious as a median real
    attack"), rather than an arbitrary fixed number.
    """
    risk_scores = np.asarray(risk_scores, dtype=np.float64)
    is_true_attack = np.asarray(is_true_attack, dtype=bool)

    benign_scores = risk_scores[~is_true_attack]
    attack_scores = risk_scores[is_true_attack]

    low_threshold = float(np.quantile(benign_scores, benign_quantile)) if len(benign_scores) else 0.4
    high_threshold = float(np.quantile(attack_scores, attack_quantile)) if len(attack_scores) else 0.7
    if high_threshold <= low_threshold:
        high_threshold = low_threshold + 1e-9
    return low_threshold, high_threshold


def risk_level_for(risk_score: float, low_threshold: float, high_threshold: float) -> str:
    if risk_score >= high_threshold:
        return "High"
    if risk_score >= low_threshold:
        return "Medium"
    return "Low"


def risk_levels_for(risk_scores: np.ndarray, low_threshold: float, high_threshold: float) -> np.ndarray:
    risk_scores = np.asarray(risk_scores, dtype=np.float64)
    levels = np.full(risk_scores.shape, "Low", dtype=object)
    levels[risk_scores >= low_threshold] = "Medium"
    levels[risk_scores >= high_threshold] = "High"
    return levels
