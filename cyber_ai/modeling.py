from __future__ import annotations

from pathlib import Path

import numpy as np
import tensorflow as tf
from sklearn.metrics import precision_recall_curve


def set_global_seed(seed: int) -> None:
    np.random.seed(seed)
    tf.keras.utils.set_random_seed(seed)


def build_sequence_autoencoder(
    window_size: int,
    n_features: int,
    latent_dim: int = 32,
    lstm_units: int = 64,
    dropout: float = 0.25,
    learning_rate: float = 0.001,
) -> tf.keras.Model:
    inputs = tf.keras.Input(shape=(window_size, n_features), name="traffic_window")
    encoded = tf.keras.layers.LSTM(lstm_units, return_sequences=False, name="encoder_lstm")(inputs)
    encoded = tf.keras.layers.Dropout(dropout, name="encoder_dropout")(encoded)
    bottleneck = tf.keras.layers.Dense(latent_dim, activation="relu", name="latent_behavior")(encoded)
    repeated = tf.keras.layers.RepeatVector(window_size, name="repeat_latent")(bottleneck)
    decoded = tf.keras.layers.LSTM(lstm_units, return_sequences=True, name="decoder_lstm")(repeated)
    decoded = tf.keras.layers.Dropout(dropout, name="decoder_dropout")(decoded)
    outputs = tf.keras.layers.TimeDistributed(
        tf.keras.layers.Dense(n_features),
        name="reconstructed_window",
    )(decoded)

    model = tf.keras.Model(inputs, outputs, name="sequence_autoencoder")
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
        loss="mse",
    )
    return model


def build_bilstm_classifier(
    window_size: int,
    n_features: int,
    n_classes: int,
    lstm_units: int = 64,
    dropout: float = 0.25,
    learning_rate: float = 0.001,
) -> tf.keras.Model:
    inputs = tf.keras.Input(shape=(window_size, n_features), name="traffic_window")
    x = tf.keras.layers.Bidirectional(
        tf.keras.layers.LSTM(lstm_units, return_sequences=True),
        name="bilstm_context",
    )(inputs)
    x = tf.keras.layers.Dropout(dropout, name="context_dropout")(x)
    x = tf.keras.layers.Bidirectional(
        tf.keras.layers.LSTM(max(16, lstm_units // 2), return_sequences=False),
        name="bilstm_summary",
    )(x)
    x = tf.keras.layers.Dense(64, activation="relu", name="classification_hidden")(x)
    x = tf.keras.layers.Dropout(dropout, name="classification_dropout")(x)
    outputs = tf.keras.layers.Dense(n_classes, activation="softmax", name="threat_type")(x)

    model = tf.keras.Model(inputs, outputs, name="bilstm_threat_classifier")
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


def reconstruction_errors(model: tf.keras.Model, sequence) -> np.ndarray:
    errors: list[np.ndarray] = []
    for batch_index in range(len(sequence)):
        batch = sequence[batch_index]
        windows = batch[0] if isinstance(batch, tuple) else batch
        reconstructed = model.predict(windows, verbose=0)
        errors.append(np.mean(np.square(windows - reconstructed), axis=(1, 2)))
    return np.concatenate(errors, axis=0) if errors else np.array([], dtype=np.float32)


def supervised_f1_threshold(
    errors: np.ndarray,
    binary_targets: np.ndarray,
    fallback_quantile: float = 0.995,
) -> tuple[float, dict[str, float]]:
    errors = np.asarray(errors, dtype=np.float64)
    binary_targets = np.asarray(binary_targets, dtype=np.int64)

    if len(errors) == 0:
        raise ValueError("Cannot calibrate anomaly threshold without reconstruction errors.")
    if len(np.unique(binary_targets)) < 2:
        threshold = float(np.quantile(errors, fallback_quantile))
        return threshold, {
            "threshold": threshold,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "strategy": "fallback_quantile",
        }

    precision, recall, thresholds = precision_recall_curve(binary_targets, errors)
    if len(thresholds) == 0:
        threshold = float(np.quantile(errors, fallback_quantile))
        return threshold, {
            "threshold": threshold,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "strategy": "fallback_quantile",
        }

    precision = precision[:-1]
    recall = recall[:-1]
    f1_scores = (2 * precision * recall) / np.maximum(precision + recall, 1e-12)
    best_index = int(np.nanargmax(f1_scores))
    threshold = float(thresholds[best_index])
    return threshold, {
        "threshold": threshold,
        "precision": float(precision[best_index]),
        "recall": float(recall[best_index]),
        "f1": float(f1_scores[best_index]),
        "strategy": "supervised_f1",
    }


def balanced_accuracy_threshold(
    errors: np.ndarray,
    binary_targets: np.ndarray,
    fallback_quantile: float = 0.995,
) -> tuple[float, dict[str, float]]:
    errors = np.asarray(errors, dtype=np.float64)
    binary_targets = np.asarray(binary_targets, dtype=np.int64)

    if len(errors) == 0:
        raise ValueError("Cannot calibrate anomaly threshold without reconstruction errors.")
    if len(np.unique(binary_targets)) < 2:
        threshold = float(np.quantile(errors, fallback_quantile))
        return threshold, {
            "threshold": threshold,
            "true_positive_rate": 0.0,
            "true_negative_rate": 0.0,
            "balanced_accuracy": 0.0,
            "strategy": "fallback_quantile",
        }

    thresholds = np.unique(np.quantile(errors, np.linspace(0.0, 1.0, 2001)))
    best: tuple[float, float, float, float] | None = None
    for threshold in thresholds:
        predictions = (errors > threshold).astype(np.int64)
        positives = binary_targets == 1
        negatives = ~positives
        true_positive_rate = float(predictions[positives].mean()) if positives.any() else 0.0
        true_negative_rate = float((predictions[negatives] == 0).mean()) if negatives.any() else 0.0
        balanced_accuracy = (true_positive_rate + true_negative_rate) / 2.0
        candidate = (balanced_accuracy, true_positive_rate, true_negative_rate, float(threshold))
        if best is None or candidate > best:
            best = candidate

    assert best is not None
    balanced_accuracy, true_positive_rate, true_negative_rate, threshold = best
    return threshold, {
        "threshold": threshold,
        "true_positive_rate": true_positive_rate,
        "true_negative_rate": true_negative_rate,
        "balanced_accuracy": balanced_accuracy,
        "strategy": "balanced_accuracy",
    }


def classifier_probabilities(model: tf.keras.Model, sequence) -> np.ndarray:
    probabilities: list[np.ndarray] = []
    for batch_index in range(len(sequence)):
        batch = sequence[batch_index]
        windows = batch[0] if isinstance(batch, tuple) else batch
        probabilities.append(model.predict(windows, verbose=0))
    return np.concatenate(probabilities, axis=0) if probabilities else np.empty((0, 0))


def save_model_summary(model: tf.keras.Model, path: str | Path) -> None:
    summary_path = Path(path)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", encoding="utf-8") as handle:
        model.summary(print_fn=lambda line: handle.write(line + "\n"))
