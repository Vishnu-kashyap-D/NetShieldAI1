from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from cyber_ai.data import SOURCE_COLUMN, build_window_starts_grouped, clean_raw_dataframe, dataframe_to_features
from cyber_ai.explain import build_autoencoder_error_model
from cyber_ai.hybrid_risk import compute_risk_score, normalize_anomaly_score, risk_levels_for
from cyber_ai.reporting import write_json
from cyber_ai.windowing import materialize_windows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure real per-window detection latency (Autoencoder-only, "
        "Autoencoder+BiLSTM, and the full pipeline including SHAP)."
    )
    parser.add_argument("--input-csv", action="append", required=True, help="Traffic CSV to sample windows from.")
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--num-windows", type=int, default=500, help="How many windows to time.")
    parser.add_argument("--shap-background", type=int, default=20, help="Background windows for the SHAP explainers.")
    parser.add_argument("--shap-nsamples", type=int, default=100)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def _load_frame(csv_paths: list[str]) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for csv_path in csv_paths:
        path = Path(csv_path)
        frame = pd.read_csv(path, low_memory=False)
        frames.append(clean_raw_dataframe(frame, source_name=path.name))
    return pd.concat(frames, axis=0, ignore_index=True)


def _percentiles(latencies_ms: list[float]) -> dict[str, float]:
    if not latencies_ms:
        return {"count": 0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    values = np.asarray(latencies_ms)
    return {
        "count": int(len(values)),
        "mean_ms": float(values.mean()),
        "p50_ms": float(np.percentile(values, 50)),
        "p95_ms": float(np.percentile(values, 95)),
        "max_ms": float(values.max()),
    }


def main() -> None:
    args = parse_args()
    artifacts_dir = Path(args.artifacts_dir)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")
    feature_names = preprocessing["feature_names"]
    imputer = preprocessing["imputer"]
    scaler = preprocessing["scaler"]
    window_size = int(preprocessing["window_size"])
    stride = int(preprocessing["stride"])
    anomaly_threshold = float(preprocessing["anomaly_threshold"])
    anomaly_score_low = float(preprocessing["anomaly_score_low"])
    anomaly_score_high = float(preprocessing["anomaly_score_high"])
    risk_low_threshold = float(preprocessing["risk_low_threshold"])
    risk_high_threshold = float(preprocessing["risk_high_threshold"])

    autoencoder = tf.keras.models.load_model(artifacts_dir / "models" / "autoencoder.keras")
    classifier = tf.keras.models.load_model(artifacts_dir / "models" / "bilstm_classifier.keras")

    import shap

    df = _load_frame(args.input_csv)
    X_raw, _, _ = dataframe_to_features(df, feature_names=feature_names)
    X = scaler.transform(imputer.transform(X_raw)).astype(np.float32)

    starts = build_window_starts_grouped(df[SOURCE_COLUMN].to_numpy(), window_size, stride)
    if len(starts) == 0:
        raise ValueError("No windows were created. Check the input CSV(s) and window size.")

    rng = np.random.RandomState(args.random_state)
    if len(starts) > args.num_windows:
        sample_starts = np.sort(rng.choice(starts, size=args.num_windows, replace=False))
    else:
        sample_starts = starts

    background_positions = np.linspace(0, len(starts) - 1, min(args.shap_background, len(starts)), dtype=np.int64)
    background_windows = materialize_windows(X, starts[background_positions], window_size)
    error_model = build_autoencoder_error_model(autoencoder)
    classifier_explainer = shap.GradientExplainer(classifier, background_windows)
    autoencoder_explainer = shap.GradientExplainer(error_model, background_windows)

    # A model's / explainer's first call always pays a one-off TF tracing cost that a
    # long-running service would only pay once at startup, not per request — warm up before
    # the timed loop so the measured distribution reflects steady-state serving latency.
    warm_window = materialize_windows(X, sample_starts[:1], window_size)
    autoencoder(warm_window, training=False)
    classifier(warm_window, training=False)
    classifier_explainer.shap_values(warm_window, nsamples=args.shap_nsamples)
    autoencoder_explainer.shap_values(warm_window, nsamples=args.shap_nsamples)

    autoencoder_only_ms: list[float] = []
    autoencoder_plus_bilstm_ms: list[float] = []
    shap_only_ms: list[float] = []
    full_pipeline_ms: list[float] = []
    risk_level_counts = {"Low": 0, "Medium": 0, "High": 0}

    for start in sample_starts:
        window = materialize_windows(X, np.array([start]), window_size)

        t0 = time.perf_counter()
        reconstructed = autoencoder(window, training=False).numpy()
        error = float(np.mean(np.square(window - reconstructed)))
        t1 = time.perf_counter()
        autoencoder_only_ms.append((t1 - t0) * 1000.0)

        is_anomaly = error > anomaly_threshold
        normalized_error = float(normalize_anomaly_score(np.array([error]), anomaly_score_low, anomaly_score_high)[0])

        class_probability = np.nan
        t2 = t1
        if is_anomaly:
            probabilities = classifier(window, training=False).numpy()
            class_probability = float(probabilities.max())
            t2 = time.perf_counter()
            autoencoder_plus_bilstm_ms.append((t1 - t0 + t2 - t1) * 1000.0)

        risk_score = float(compute_risk_score(np.array([normalized_error]), np.array([class_probability]))[0])
        risk_level = str(risk_levels_for(np.array([risk_score]), risk_low_threshold, risk_high_threshold)[0])
        risk_level_counts[risk_level] += 1

        t3 = t2
        if risk_level != "Low":
            t_shap_start = time.perf_counter()
            classifier_explainer.shap_values(window, nsamples=args.shap_nsamples)
            autoencoder_explainer.shap_values(window, nsamples=args.shap_nsamples)
            t3 = time.perf_counter()
            shap_only_ms.append((t3 - t_shap_start) * 1000.0)

        full_pipeline_ms.append((t3 - t0) * 1000.0)

    report = {
        "num_windows_sampled": int(len(sample_starts)),
        "risk_level_counts": risk_level_counts,
        "autoencoder_only": _percentiles(autoencoder_only_ms),
        "autoencoder_plus_bilstm": _percentiles(autoencoder_plus_bilstm_ms),
        "shap_only": _percentiles(shap_only_ms),
        "full_pipeline_blended": _percentiles(full_pipeline_ms),
        "raw_latencies_ms": {
            "autoencoder_only": autoencoder_only_ms,
            "autoencoder_plus_bilstm": autoencoder_plus_bilstm_ms,
            "shap_only": shap_only_ms,
            "full_pipeline_blended": full_pipeline_ms,
        },
        "notes": (
            "autoencoder_only measures every sampled window. autoencoder_plus_bilstm and "
            "shap_only measure only the subset of windows that actually reached that stage "
            "(matches the sequential-gate architecture). full_pipeline_blended is the "
            "realistic end-to-end latency across the actual mix of Normal/Medium/High "
            "windows, i.e. what a live stream would experience on average."
        ),
    }
    write_json(reports_dir / "latency_benchmark.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
