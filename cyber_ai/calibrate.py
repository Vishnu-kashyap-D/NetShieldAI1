from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import tensorflow as tf
from sklearn.metrics import classification_report, confusion_matrix

from cyber_ai.data import (
    SOURCE_COLUMN,
    build_window_starts_grouped,
    dataframe_to_features,
    load_cicids2017,
    sample_window_starts_by_class,
    split_window_starts,
    window_labels,
)
from cyber_ai.hybrid_risk import (
    calibrate_anomaly_score_range,
    calibrate_risk_levels,
    compute_risk_score,
    normalize_anomaly_score,
    risk_levels_for,
)
from cyber_ai.modeling import (
    balanced_accuracy_threshold,
    classifier_probabilities,
    reconstruction_errors,
    supervised_f1_threshold,
)
from cyber_ai.reporting import write_json
from cyber_ai.windowing import WindowSequence


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recalibrate the Autoencoder anomaly threshold.")
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument(
        "--strategy",
        default="balanced_accuracy",
        choices=["balanced_accuracy", "supervised_f1", "quantile"],
    )
    parser.add_argument("--quantile", type=float, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    artifacts_dir = Path(args.artifacts_dir)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    preprocessing_path = artifacts_dir / "preprocessing.joblib"
    preprocessing = joblib.load(preprocessing_path)
    config = preprocessing["config"]
    data_config = config["data"]
    preprocessing_config = config["preprocessing"]
    anomaly_config = config["anomaly"]

    window_size = int(preprocessing["window_size"])
    stride = int(preprocessing["stride"])
    benign_id = int(preprocessing["benign_id"])
    feature_names = preprocessing["feature_names"]
    raw_label_encoder = preprocessing["raw_label_encoder"]
    imputer = preprocessing["imputer"]
    scaler = preprocessing["scaler"]
    quantile = float(args.quantile if args.quantile is not None else anomaly_config.get("threshold_quantile", 0.995))

    random_state = int(data_config["random_state"])
    df = load_cicids2017(
        data_dir=data_config["data_dir"],
        feedback_csvs=data_config.get("feedback_csvs") or [],
        random_state=random_state,
    )
    X_raw, raw_labels, _ = dataframe_to_features(df, feature_names=feature_names)
    y_raw = raw_label_encoder.transform(raw_labels)
    X = scaler.transform(imputer.transform(X_raw)).astype(np.float32)

    starts = build_window_starts_grouped(df[SOURCE_COLUMN].to_numpy(), window_size, stride)
    max_rows_per_class = data_config.get("max_rows_per_class")
    max_rows = data_config.get("max_rows")
    if max_rows_per_class is not None:
        window_targets = window_labels(y_raw, starts, window_size)
        starts = sample_window_starts_by_class(starts, window_targets, int(max_rows_per_class), random_state)
    elif max_rows is not None and len(starts) > max_rows:
        rng = np.random.RandomState(random_state)
        starts = np.sort(rng.choice(starts, size=int(max_rows), replace=False))

    _, validation_starts, test_starts = split_window_starts(
        starts=starts,
        y=y_raw,
        window_size=window_size,
        validation_size=float(preprocessing_config["validation_size"]),
        test_size=float(preprocessing_config["test_size"]),
        random_state=int(data_config["random_state"]),
    )

    autoencoder = tf.keras.models.load_model(artifacts_dir / "models" / "autoencoder.keras")
    classifier = tf.keras.models.load_model(artifacts_dir / "models" / "bilstm_classifier.keras")
    validation_sequence = WindowSequence(
        X,
        starts=validation_starts,
        window_size=window_size,
        batch_size=256,
        target_mode="autoencoder",
        shuffle=False,
    )
    validation_errors = reconstruction_errors(autoencoder, validation_sequence)
    validation_targets = (window_labels(y_raw, validation_starts, window_size) != benign_id).astype(int)

    if args.strategy == "supervised_f1":
        threshold, threshold_report = supervised_f1_threshold(validation_errors, validation_targets, quantile)
    elif args.strategy == "balanced_accuracy":
        threshold, threshold_report = balanced_accuracy_threshold(validation_errors, validation_targets, quantile)
    else:
        threshold = float(np.quantile(validation_errors[validation_targets == 0], quantile))
        threshold_report = {
            "threshold": threshold,
            "strategy": "benign_quantile",
            "quantile": quantile,
        }

    test_sequence = WindowSequence(
        X,
        starts=test_starts,
        window_size=window_size,
        batch_size=256,
        target_mode="autoencoder",
        shuffle=False,
    )
    test_errors = reconstruction_errors(autoencoder, test_sequence)
    test_targets = (window_labels(y_raw, test_starts, window_size) != benign_id).astype(int)
    test_predictions = (test_errors > threshold).astype(int)
    anomaly_report = classification_report(
        test_targets,
        test_predictions,
        labels=[0, 1],
        target_names=["normal", "anomaly"],
        zero_division=0,
        output_dict=True,
    )

    def _fused_risk_scores(window_starts: np.ndarray, raw_errors: np.ndarray, is_anomaly_pred: np.ndarray) -> np.ndarray:
        normalized = normalize_anomaly_score(raw_errors, anomaly_score_low, anomaly_score_high)
        class_probability = np.full(len(window_starts), np.nan, dtype=np.float64)
        flagged_starts = window_starts[is_anomaly_pred]
        if len(flagged_starts) > 0:
            flagged_sequence = WindowSequence(
                X, starts=flagged_starts, window_size=window_size, batch_size=256, target_mode=None, shuffle=False
            )
            flagged_probabilities = classifier_probabilities(classifier, flagged_sequence)
            class_probability[is_anomaly_pred] = flagged_probabilities.max(axis=1)
        return compute_risk_score(normalized, class_probability)

    # The anomaly threshold just changed, so the risk-fusion calibration (which depends on
    # it) must be recomputed too, or the two would silently drift out of sync.
    anomaly_score_low, anomaly_score_high = calibrate_anomaly_score_range(validation_errors)
    validation_is_anomaly_pred = validation_errors > threshold
    validation_risk_scores = _fused_risk_scores(validation_starts, validation_errors, validation_is_anomaly_pred)
    risk_low_threshold, risk_high_threshold = calibrate_risk_levels(
        validation_risk_scores, validation_targets.astype(bool)
    )

    test_risk_scores = _fused_risk_scores(test_starts, test_errors, test_predictions.astype(bool))
    test_risk_levels = risk_levels_for(test_risk_scores, risk_low_threshold, risk_high_threshold)
    test_flagged = test_risk_levels != "Low"
    hybrid_report = classification_report(
        test_targets,
        test_flagged.astype(int),
        labels=[0, 1],
        target_names=["normal", "suspicious_or_attack"],
        zero_division=0,
        output_dict=True,
    )
    hybrid_confusion = confusion_matrix(test_targets, test_flagged.astype(int), labels=[0, 1]).tolist()
    false_positive_rate = hybrid_confusion[0][1] / sum(hybrid_confusion[0]) if sum(hybrid_confusion[0]) else 0.0
    false_negative_rate = hybrid_confusion[1][0] / sum(hybrid_confusion[1]) if sum(hybrid_confusion[1]) else 0.0
    risk_level_counts = {level: int((test_risk_levels == level).sum()) for level in ["Low", "Medium", "High"]}

    preprocessing["anomaly_threshold"] = threshold
    preprocessing["anomaly_score_low"] = anomaly_score_low
    preprocessing["anomaly_score_high"] = anomaly_score_high
    preprocessing["risk_low_threshold"] = risk_low_threshold
    preprocessing["risk_high_threshold"] = risk_high_threshold
    preprocessing["config"]["anomaly"]["threshold_strategy"] = args.strategy
    preprocessing["config"]["anomaly"]["threshold_quantile"] = quantile
    joblib.dump(preprocessing, preprocessing_path)

    training_metrics_path = reports_dir / "training_metrics.json"
    if training_metrics_path.exists():
        import json

        metrics = json.loads(training_metrics_path.read_text(encoding="utf-8"))
    else:
        metrics = {}
    metrics.setdefault("autoencoder", {})
    metrics["autoencoder"]["threshold_quantile"] = quantile
    metrics["autoencoder"]["threshold_strategy"] = args.strategy
    metrics["autoencoder"]["threshold_report"] = threshold_report
    metrics["autoencoder"]["anomaly_threshold"] = threshold
    metrics["autoencoder"]["classification_report"] = anomaly_report
    metrics["hybrid_risk"] = {
        "anomaly_score_low": anomaly_score_low,
        "anomaly_score_high": anomaly_score_high,
        "risk_low_threshold": risk_low_threshold,
        "risk_high_threshold": risk_high_threshold,
        "risk_level_counts": risk_level_counts,
        "classification_report": hybrid_report,
        "confusion_matrix": hybrid_confusion,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
    }
    write_json(training_metrics_path, metrics)

    write_json(
        reports_dir / "anomaly_threshold_calibration.json",
        {
            "threshold": threshold,
            "threshold_report": threshold_report,
            "test_classification_report": anomaly_report,
            "hybrid_risk": metrics["hybrid_risk"],
        },
    )
    print(f"Updated anomaly threshold to {threshold:.6f}")
    print(f"Saved calibration report to {(reports_dir / 'anomaly_threshold_calibration.json').resolve()}")
    print(f"Hybrid risk fusion: {risk_level_counts} (FPR={false_positive_rate:.4f}, FNR={false_negative_rate:.4f})")


if __name__ == "__main__":
    main()
