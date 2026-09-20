"""A real DetectionEngine whose two neural networks are replaced by tiny, fully predictable stand-ins.

`DetectionEngine.score_dataframe` is the code under test (windowing, thresholding, risk fusion,
record building); only the *models* are swapped, so the expected outcome of a known CSV can be worked
out by hand and asserted exactly -- independent of whatever weights happen to be in artifacts/.

How the stand-ins behave (window = 10 rows, stride = 10, 3 features):
  * "autoencoder": reconstructs every window as all zeros, so a window's reconstruction error is
    mean(x**2) over its values. A block of rows holding the value v scores v**2.
  * "classifier": says "DoS / DDoS" with probability 0.6 for a window whose values are all 2.0, and
    "Port Scanning" with probability 0.9 for anything else it is asked to classify.
  * imputer / scaler: pass values through unchanged.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from app.detection_service import DetectionEngine
from app.feature_schema import feature_schema_version

FEATURES = ["Flow Duration", "Total Fwd Packets", "Flow Bytes/s"]
CLASSES = np.array(["DoS / DDoS", "Port Scanning"], dtype=object)

ANOMALY_THRESHOLD = 1.0       # error > 1.0 => anomalous (i.e. window value > 1)
ANOMALY_SCORE_LOW = 0.0
ANOMALY_SCORE_HIGH = 16.0     # so normalized anomaly score = error / 16
RISK_LOW = 0.3
RISK_HIGH = 0.8


class _ZeroAutoencoder:
    def predict(self, windows, verbose=0):
        return np.zeros_like(windows)


class _TwoClassClassifier:
    def predict(self, windows, verbose=0):
        probabilities = np.zeros((len(windows), 2), dtype=np.float32)
        for row, window in enumerate(windows):
            if np.allclose(window, 2.0):
                probabilities[row] = [0.6, 0.4]      # DoS / DDoS, confidence 0.6
            else:
                probabilities[row] = [0.1, 0.9]      # Port Scanning, confidence 0.9
        return probabilities


class _PassThrough:
    def transform(self, values):
        return np.asarray(values, dtype=np.float64)


class _Encoder:
    def inverse_transform(self, ids):
        return CLASSES[np.asarray(ids)]


def make_engine() -> DetectionEngine:
    engine = DetectionEngine.__new__(DetectionEngine)  # skip __init__: it loads real model files
    engine.feature_names = list(FEATURES)
    engine.feature_schema_version = feature_schema_version(FEATURES)
    engine.imputer = _PassThrough()
    engine.scaler = _PassThrough()
    engine.label_encoder = _Encoder()
    engine.window_size = 10
    engine.stride = 10
    engine.anomaly_threshold = ANOMALY_THRESHOLD
    engine.anomaly_score_low = ANOMALY_SCORE_LOW
    engine.anomaly_score_high = ANOMALY_SCORE_HIGH
    engine.risk_low_threshold = RISK_LOW
    engine.risk_high_threshold = RISK_HIGH
    engine.autoencoder = _ZeroAutoencoder()
    engine.classifier = _TwoClassClassifier()
    return engine


# Four windows of 10 rows each, worked out by hand for the stand-in models above:
#
#   rows  0-9   value 0.0   error  0   -> below threshold          -> Normal,  risk 0.00 -> Low
#   rows 10-19  value 0.0   error  0   -> below threshold          -> Normal,  risk 0.00 -> Low
#   rows 20-29  value 2.0   error  4   -> anomalous, DoS / DDoS 0.6 -> risk max(4/16, 0.6) = 0.60 -> Medium
#   rows 30-39  value 4.0   error 16   -> anomalous, Port Scanning 0.9 -> risk max(16/16, 0.9) = 1.00 -> High
WINDOW_VALUES = [0.0, 0.0, 2.0, 4.0]
WINDOW_LABELS = ["BENIGN", "BENIGN", "DDoS", "PortScan"]


def known_traffic_csv(labels: list[str] | None = WINDOW_LABELS) -> bytes:
    rows = []
    for value, label in zip(WINDOW_VALUES, labels or [None] * 4):
        for _ in range(10):
            row = {name: value for name in FEATURES}
            if label is not None:
                row["Label"] = label
            rows.append(row)
    return pd.DataFrame(rows).to_csv(index=False).encode("utf-8")
