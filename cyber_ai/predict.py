from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

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
from cyber_ai.reporting import timestamp_slug, write_json
from cyber_ai.windowing import WindowSequence


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run anomaly detection and threat classification.")
    parser.add_argument("--input-csv", action="append", required=True, help="Traffic CSV to score.")
    parser.add_argument("--artifacts-dir", default="artifacts", help="Directory containing trained artifacts.")
    parser.add_argument("--reports-dir", default="reports", help="Directory for alerts and summaries.")
    parser.add_argument("--output-csv", help="Optional alert CSV output path.")
    parser.add_argument("--include-all-windows", action="store_true", help="Save every scored window.")
    parser.add_argument("--start-window", type=int, default=0, help="Skip this many generated windows before scoring.")
    parser.add_argument("--max-windows", type=int, help="Optional cap for quick scoring runs.")
    parser.add_argument("--shap", action="store_true", help="Attach SHAP top-feature explanations.")
    parser.add_argument("--shap-background", type=int, default=20, help="Background windows for SHAP.")
    parser.add_argument("--shap-samples", type=int, default=100, help="Kernel SHAP samples.")
    parser.add_argument("--shap-max-alerts", type=int, default=20, help="Max alert windows to explain.")
    return parser.parse_args()


def _load_prediction_frame(csv_paths: list[str]) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for csv_path in csv_paths:
        path = Path(csv_path)
        frame = pd.read_csv(path, low_memory=False)
        frames.append(clean_raw_dataframe(frame, source_name=path.name))
    return pd.concat(frames, axis=0, ignore_index=True)


def _choose_background_starts(starts: np.ndarray, max_background: int) -> np.ndarray:
    if len(starts) <= max_background:
        return starts
    positions = np.linspace(0, len(starts) - 1, max_background, dtype=np.int64)
    return starts[positions]


def main() -> None:
    args = parse_args()
    artifacts_dir = Path(args.artifacts_dir)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")
    feature_names = preprocessing["feature_names"]
    imputer = preprocessing["imputer"]
    scaler = preprocessing["scaler"]
    label_encoder = preprocessing["label_encoder"]
    window_size = int(preprocessing["window_size"])
    stride = int(preprocessing["stride"])
    anomaly_threshold = float(preprocessing["anomaly_threshold"])
    anomaly_score_low = float(preprocessing["anomaly_score_low"])
    anomaly_score_high = float(preprocessing["anomaly_score_high"])
    risk_low_threshold = float(preprocessing["risk_low_threshold"])
    risk_high_threshold = float(preprocessing["risk_high_threshold"])
    normal_label = preprocessing.get("normal_decision_label", NORMAL_DECISION_LABEL)

    autoencoder = tf.keras.models.load_model(artifacts_dir / "models" / "autoencoder.keras")
    classifier = tf.keras.models.load_model(artifacts_dir / "models" / "bilstm_classifier.keras")

    df = _load_prediction_frame(args.input_csv)
    X_raw, raw_labels, _ = dataframe_to_features(df, feature_names=feature_names)
    X = scaler.transform(imputer.transform(X_raw)).astype(np.float32)

    starts = build_window_starts_grouped(df[SOURCE_COLUMN].to_numpy(), window_size, stride)
    if args.start_window:
        starts = starts[args.start_window :]
    if args.max_windows is not None:
        starts = starts[: args.max_windows]
    if len(starts) == 0:
        raise ValueError("No windows were created. Check input size, window size, and stride.")

    ae_sequence = WindowSequence(
        X,
        starts=starts,
        window_size=window_size,
        batch_size=256,
        target_mode="autoencoder",
        shuffle=False,
    )

    anomaly_scores = reconstruction_errors(autoencoder, ae_sequence)
    is_anomaly = anomaly_scores > anomaly_threshold
    classifier_positions = np.where(is_anomaly)[0]
    classifier_starts = starts[classifier_positions]

    predicted_labels = np.full(len(starts), NORMAL_DECISION_LABEL, dtype=object)
    confidences = np.zeros(len(starts), dtype=np.float32)
    classifier_confidence_for_risk = np.full(len(starts), np.nan, dtype=np.float64)
    if len(classifier_starts) > 0:
        prediction_sequence = WindowSequence(
            X,
            starts=classifier_starts,
            window_size=window_size,
            batch_size=256,
            target_mode=None,
            shuffle=False,
        )
        probabilities = classifier_probabilities(classifier, prediction_sequence)
        predicted_ids = probabilities.argmax(axis=1)
        predicted_labels[classifier_positions] = label_encoder.inverse_transform(predicted_ids)
        max_probabilities = probabilities.max(axis=1)
        confidences[classifier_positions] = max_probabilities
        classifier_confidence_for_risk[classifier_positions] = max_probabilities

    normalized_anomaly_scores = normalize_anomaly_score(anomaly_scores, anomaly_score_low, anomaly_score_high)
    risk_scores = compute_risk_score(normalized_anomaly_scores, classifier_confidence_for_risk)
    risk_levels = risk_levels_for(risk_scores, risk_low_threshold, risk_high_threshold)

    # Alert-worthy per the hybrid risk fusion (Medium/High), not just "did the anomaly gate
    # fire" — a window can score Medium/High from a borderline anomaly score alone, or a
    # window that did reach the classifier can still resolve to Low if nothing panned out.
    keep_mask = np.ones(len(starts), dtype=bool) if args.include_all_windows else (risk_levels != "Low")
    kept_positions = np.where(keep_mask)[0]
    kept_starts = starts[kept_positions]

    classifier_explanations: dict[int, str] = {}
    anomaly_explanations: dict[int, str] = {}
    if args.shap and len(classifier_starts) > 0:
        explain_starts = classifier_starts[: args.shap_max_alerts]
        background_starts = _choose_background_starts(starts, args.shap_background)
        classifier_explanations = explain_classifier_windows(
            classifier,
            X,
            explain_starts,
            background_starts,
            window_size,
            feature_names,
            nsamples=args.shap_samples,
        )
        anomaly_explanations = explain_autoencoder_windows(
            autoencoder,
            X,
            explain_starts,
            background_starts,
            window_size,
            feature_names,
            nsamples=args.shap_samples,
        )

    records: list[dict] = []
    for position in kept_positions:
        start = int(starts[position])
        end = start + window_size - 1
        source_row = df.iloc[end]
        predicted_label = normalize_label(predicted_labels[position])
        actual_label = normalize_label(raw_labels[end]) if raw_labels is not None else ""
        actual_category = to_attack_category(actual_label) or NORMAL_DECISION_LABEL
        record = {
            "window_start": start,
            "window_end": end,
            "source_file": source_row.get(SOURCE_COLUMN, ""),
            "actual_label": actual_label,
            "actual_category": actual_category,
            "predicted_label": predicted_label,
            "confidence": float(confidences[position]),
            "anomaly_score": float(anomaly_scores[position]),
            "anomaly_threshold": anomaly_threshold,
            "is_anomaly": bool(is_anomaly[position]),
            "pipeline_action": "Classified and alerted" if is_anomaly[position] else "Ignored as normal",
            "risk_score": float(risk_scores[position]),
            "risk_level": risk_levels[position],
            "top_classifier_features": classifier_explanations.get(start, ""),
            "top_anomaly_features": anomaly_explanations.get(start, ""),
        }
        for feature in feature_names:
            record[feature] = source_row.get(feature, np.nan)
        records.append(record)

    output_path = Path(args.output_csv) if args.output_csv else reports_dir / f"alerts_{timestamp_slug()}.csv"
    alerts = pd.DataFrame(records)
    alerts.to_csv(output_path, index=False)

    summary = {
        "input_rows": int(len(df)),
        "windows_scored": int(len(starts)),
        "anomalous_windows": int(is_anomaly.sum()),
        "alerts_written": int(len(alerts)),
        "anomaly_threshold": anomaly_threshold,
        "output_csv": str(output_path.resolve()),
        "predicted_label_counts": {
            str(label): int(count) for label, count in pd.Series(predicted_labels).value_counts().items()
        },
        "risk_level_counts": {
            str(level): int(count) for level, count in pd.Series(risk_levels).value_counts().items()
        },
    }
    write_json(output_path.with_suffix(".summary.json"), summary)

    print(f"Scored {len(starts)} windows.")
    print(f"Wrote {len(alerts)} alert rows to {output_path.resolve()}")


if __name__ == "__main__":
    main()
