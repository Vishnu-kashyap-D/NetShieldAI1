from __future__ import annotations

import json

import numpy as np
import tensorflow as tf

from cyber_ai.windowing import materialize_windows


def _require_shap():
    try:
        import shap
    except ImportError as exc:
        raise RuntimeError(
            "SHAP is not installed. Run `pip install -r requirements.txt` and retry with SHAP enabled."
        ) from exc
    return shap


def _top_features(scores: np.ndarray, feature_names: list[str], top_k: int) -> list[dict[str, float | str]]:
    top_indices = np.argsort(scores)[::-1][:top_k]
    return [
        {"feature": feature_names[index], "mean_abs_shap": float(scores[index])}
        for index in top_indices
    ]


def _per_sample_scores(
    shap_values, sample_index: int, output_index: int, n_features: int
) -> np.ndarray:
    """Extract one sample's (n_features,) importance vector from a GradientExplainer result.

    Different shap versions shape this differently: older versions return a list with one
    (batch, window_size, n_features) array per output; the version this project pins
    (>=0.45) returns a single (batch, window_size, n_features, n_outputs) array with the
    output dimension last. Handle both rather than assume one.
    """
    if isinstance(shap_values, list):
        values = shap_values[output_index][sample_index]
    else:
        values = shap_values[sample_index]
        if values.ndim == 3:
            values = values[..., output_index]
    return np.abs(values).mean(axis=0).reshape(n_features)


def build_autoencoder_error_model(autoencoder: tf.keras.Model) -> tf.keras.Model:
    """Wrap the Autoencoder so its output is the scalar anomaly score, not the reconstruction.

    GradientExplainer explains a model's actual output with respect to its input — the
    Autoencoder's own output is the reconstruction itself, not "how anomalous is this," so
    a plain GradientExplainer on the raw model would explain the wrong thing. This wrapper
    keeps everything end-to-end differentiable (a Lambda layer, not a Python callback) and
    reduces to exactly the same scalar `reconstruction_errors()` computes in modeling.py
    (mean squared error over both the time and feature axes) — the real number the anomaly
    threshold gate acts on — so what gets explained is the actual detection signal.
    GradientExplainer also requires a vector/scalar output, not the raw 3-D reconstruction.
    """
    squared_error = tf.keras.layers.Lambda(
        lambda tensors: tf.reduce_mean(tf.square(tensors[0] - tensors[1]), axis=[1, 2]),
        name="scalar_reconstruction_error",
    )([autoencoder.input, autoencoder.output])
    return tf.keras.Model(autoencoder.input, squared_error)


def explain_classifier_windows(
    model: tf.keras.Model,
    X: np.ndarray,
    starts: np.ndarray,
    background_starts: np.ndarray,
    window_size: int,
    feature_names: list[str],
    top_k: int = 8,
    nsamples: int = 100,
) -> dict[int, str]:
    target_windows = materialize_windows(X, starts, window_size)
    background_windows = materialize_windows(X, background_starts, window_size)

    probabilities = model.predict(target_windows, verbose=0)
    predicted_classes = probabilities.argmax(axis=1)

    shap = _require_shap()
    explainer = shap.GradientExplainer(model, background_windows)
    shap_values = explainer.shap_values(target_windows, nsamples=nsamples)

    n_features = len(feature_names)
    explanations: dict[int, str] = {}
    for index, start in enumerate(starts):
        scores = _per_sample_scores(shap_values, index, int(predicted_classes[index]), n_features)
        explanations[int(start)] = json.dumps(_top_features(scores, feature_names, top_k))
    return explanations


def explain_autoencoder_windows(
    model: tf.keras.Model,
    X: np.ndarray,
    starts: np.ndarray,
    background_starts: np.ndarray,
    window_size: int,
    feature_names: list[str],
    top_k: int = 8,
    nsamples: int = 100,
) -> dict[int, str]:
    target_windows = materialize_windows(X, starts, window_size)
    background_windows = materialize_windows(X, background_starts, window_size)

    error_model = build_autoencoder_error_model(model)

    shap = _require_shap()
    explainer = shap.GradientExplainer(error_model, background_windows)
    shap_values = explainer.shap_values(target_windows, nsamples=nsamples)

    n_features = len(feature_names)
    explanations: dict[int, str] = {}
    for index, start in enumerate(starts):
        scores = _per_sample_scores(shap_values, index, 0, n_features)
        explanations[int(start)] = json.dumps(_top_features(scores, feature_names, top_k))
    return explanations
