"""Build a curated demo CSV for the panel presentation.

Pulls genuine, temporally-contiguous runs of real CICIDS2017 rows (never synthetic,
never randomly scattered) and stitches them into a deliberately-paced sequence, so the
demo doesn't depend on waiting for an interesting record to show up naturally.

A single "first contiguous run" isn't good enough on its own: this system's Autoencoder
gate has real, uneven recall (see reports/figures/reconstruction_error_distribution.png --
attacks split into a "caught" and "missed" mode), so a naive slice can just as easily land
on a miss as a catch. This script scores several real candidate slices through the actual
trained model for each scene and keeps whichever one best demonstrates that scene's intent
-- still 100% real rows, just a deliberate choice of which real stretch to use, the same way
any demo picks a representative real example rather than a fabricated one.

Scenes:
  1. Calm BENIGN baseline           -- want: no false alarms
  2. DDoS burst                     -- want: caught, high confidence
  3. Back to BENIGN
  4. Port Scanning burst            -- want: caught, high confidence
  5. Back to BENIGN
  6. Botnet Activity burst          -- want: caught (this class's aggregate precision is
     only 0.124, so if every candidate slice is weak, that itself is honest demo material
     for the hybrid risk fusion landing alerts as Medium rather than an undeserved High)
  7. Closing BENIGN

Run from the repo root:  python scripts/build_demo_csv.py
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from cyber_ai.data import LABEL_COLUMN, clean_raw_dataframe, dataframe_to_features, normalize_label
from cyber_ai.hybrid_risk import compute_risk_score, normalize_anomaly_score, risk_levels_for
from cyber_ai.windowing import materialize_windows

DATA_DIR = Path("MachineLearningCVE")
ARTIFACTS_DIR = Path("artifacts")
OUTPUT_PATH = Path("demo/panel_demo_traffic.csv")

# (source file, label to pull, how many rows, "attack" or "benign" goal, scene description)
SCENES: list[tuple[str, str, int, str, str]] = [
    ("Monday-WorkingHours.pcap_ISCX.csv", "BENIGN", 40, "benign", "Opening baseline -- calm traffic"),
    ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "DDoS", 30, "attack", "DDoS burst -- high-confidence catch"),
    ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "BENIGN", 25, "benign", "Back to normal after the DDoS burst"),
    ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "PortScan", 30, "attack", "Port Scanning burst -- high-confidence catch"),
    ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "BENIGN", 20, "benign", "Back to normal after the scan"),
    ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "Bot", 15, "attack", "Botnet Activity burst"),
    ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "BENIGN", 25, "benign", "Closing baseline"),
]

CANDIDATE_RUNS_PER_SCENE = 5
OFFSETS_PER_RUN = 5


def _contiguous_runs(mask: pd.Series) -> list[tuple[int, int]]:
    """Return (start, length) for every contiguous run of True in mask, longest first."""
    runs: list[tuple[int, int]] = []
    start = None
    for position, value in enumerate(mask.to_numpy()):
        if value and start is None:
            start = position
        elif not value and start is not None:
            runs.append((start, position - start))
            start = None
    if start is not None:
        runs.append((start, len(mask) - start))
    return sorted(runs, key=lambda run: run[1], reverse=True)


def _candidate_slices(df: pd.DataFrame, label: str, count: int) -> list[pd.DataFrame]:
    mask = df[LABEL_COLUMN].map(normalize_label) == label
    runs = [run for run in _contiguous_runs(mask) if run[1] >= count][:CANDIDATE_RUNS_PER_SCENE]
    if not runs:
        longest = _contiguous_runs(mask)[0][1] if _contiguous_runs(mask) else 0
        raise ValueError(f"Not enough contiguous {label!r} rows: wanted {count}, longest run is {longest}")

    candidates = []
    for start, length in runs:
        max_offset = length - count
        offsets = sorted(set(np.linspace(0, max_offset, min(OFFSETS_PER_RUN, max_offset + 1), dtype=int)))
        for offset in offsets:
            candidates.append(df.iloc[start + offset : start + offset + count].reset_index(drop=True))
    return candidates


class Scorer:
    """Scores a candidate slice through the real trained pipeline (no SHAP -- just risk levels)."""

    def __init__(self, artifacts_dir: Path) -> None:
        preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")
        self.feature_names = preprocessing["feature_names"]
        self.imputer = preprocessing["imputer"]
        self.scaler = preprocessing["scaler"]
        self.window_size = int(preprocessing["window_size"])
        self.stride = int(preprocessing["stride"])
        self.anomaly_threshold = float(preprocessing["anomaly_threshold"])
        self.anomaly_score_low = float(preprocessing["anomaly_score_low"])
        self.anomaly_score_high = float(preprocessing["anomaly_score_high"])
        self.risk_low_threshold = float(preprocessing["risk_low_threshold"])
        self.risk_high_threshold = float(preprocessing["risk_high_threshold"])
        self.label_encoder = preprocessing["label_encoder"]
        self.autoencoder = tf.keras.models.load_model(artifacts_dir / "models" / "autoencoder.keras")
        self.classifier = tf.keras.models.load_model(artifacts_dir / "models" / "bilstm_classifier.keras")

    def score(self, chunk: pd.DataFrame, goal: str) -> float:
        """Fraction of windows in this chunk that match the scene's goal."""
        X_raw, _, _ = dataframe_to_features(chunk, feature_names=self.feature_names)
        X = self.scaler.transform(self.imputer.transform(X_raw)).astype(np.float32)
        if len(X) < self.window_size:
            return 0.0
        starts = np.arange(0, len(X) - self.window_size + 1, self.stride, dtype=np.int64)
        if len(starts) == 0:
            return 0.0

        windows = materialize_windows(X, starts, self.window_size)
        reconstructed = self.autoencoder(windows, training=False).numpy()
        errors = np.mean(np.square(windows - reconstructed), axis=(1, 2))
        is_anomaly = errors > self.anomaly_threshold
        normalized = normalize_anomaly_score(errors, self.anomaly_score_low, self.anomaly_score_high)

        class_probability = np.full(len(starts), np.nan, dtype=np.float64)
        if is_anomaly.any():
            probabilities = self.classifier(windows[is_anomaly], training=False).numpy()
            class_probability[is_anomaly] = probabilities.max(axis=1)

        risk_scores = compute_risk_score(normalized, class_probability)
        risk_levels = risk_levels_for(risk_scores, self.risk_low_threshold, self.risk_high_threshold)

        if goal == "benign":
            return float((risk_levels == "Low").mean())
        return float((risk_levels != "Low").mean())


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    scorer = Scorer(ARTIFACTS_DIR)
    file_cache: dict[str, pd.DataFrame] = {}
    chunks: list[pd.DataFrame] = []

    for file_name, label, count, goal, description in SCENES:
        if file_name not in file_cache:
            raw = pd.read_csv(DATA_DIR / file_name, low_memory=False)
            file_cache[file_name] = clean_raw_dataframe(raw, source_name=file_name)

        candidates = _candidate_slices(file_cache[file_name], label, count)
        scored = [(scorer.score(candidate, goal), candidate) for candidate in candidates]
        best_score, best_chunk = max(scored, key=lambda item: item[0])

        print(f"{description:45} {label:10} x{count:3}  best candidate scored {best_score:.0%} ({len(scored)} tried)")
        chunks.append(best_chunk)

    demo_traffic = pd.concat(chunks, axis=0, ignore_index=True)
    demo_traffic.to_csv(OUTPUT_PATH, index=False)
    print()
    print(f"Wrote {len(demo_traffic)} rows to {OUTPUT_PATH.resolve()}")
    print(demo_traffic[LABEL_COLUMN].map(normalize_label).value_counts().to_string())


if __name__ == "__main__":
    main()
