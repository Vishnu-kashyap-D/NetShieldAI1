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


# What a signed SHAP value means for each explainer, relative to the actual output being
# explained (see explain_classifier_windows / build_autoencoder_error_model below). This is
# the single source of truth for that interpretation -- the chat backend quotes it verbatim
# instead of re-deriving or restating it, so the explanation given to an analyst always
# matches what the underlying computation actually supports.
SHAP_DIRECTION_MEANING: dict[str, str] = {
    "classifier": (
        "This SHAP value explains the predicted class's softmax probability specifically (not "
        "a pre-softmax logit, and not any other class's probability), and it is relative to the "
        "background sample used for this particular explanation (a handful of windows from the "
        "same batch, not a fixed 'normal traffic' reference -- a different background sample "
        "could shift the exact numbers). Positive means this feature's value increased the "
        "predicted class's probability relative to that background. Negative means it decreased "
        "the predicted class's probability relative to that background -- this only means "
        "'lower than it otherwise would have been,' not 'toward BENIGN specifically': because "
        "softmax probabilities across all seven categories are coupled (they must sum to 1), a "
        "negative value can reflect probability mass shifting toward any one or more of the "
        "other six categories, and this data does not identify which. A SHAP value is an "
        "attribution of the model's own output, not proof that the feature caused the traffic "
        "to be an attack (or caused it not to be)."
    ),
    "anomaly": (
        "This SHAP value explains the Autoencoder's scalar reconstruction-error output (see "
        "build_autoencoder_error_model), relative to the background sample used for this "
        "particular explanation (a handful of windows from the same batch, not a fixed 'normal "
        "traffic' reference -- a different background sample could shift the exact numbers). "
        "Positive means this feature's value increased the reconstruction-error output relative "
        "to that background (made the window look more anomalous). Negative means it decreased "
        "the reconstruction-error output relative to that background (made the window look more "
        "like normal/benign traffic, i.e. easier for the Autoencoder to reconstruct). A SHAP "
        "value is an attribution of the model's own output, not proof that the feature caused "
        "the traffic to be anomalous."
    ),
}


def _direction_for(value: float) -> str:
    if value > 1e-12:
        return "positive"
    if value < -1e-12:
        return "negative"
    return "neutral"


def _top_features(
    mean_signed: np.ndarray, mean_abs: np.ndarray, feature_names: list[str], top_k: int
) -> list[dict[str, float | str]]:
    # Ranked by mean_abs (unsigned importance/magnitude) -- unchanged from before this data
    # gained signed values, so "top-k contributing features" still means "most important
    # regardless of direction," not "most positive."
    top_indices = np.argsort(mean_abs)[::-1][:top_k]
    return [
        {
            "feature": feature_names[index],
            "shap_value": float(mean_signed[index]),
            "mean_abs_shap": float(mean_abs[index]),
            "direction": _direction_for(float(mean_signed[index])),
        }
        for index in top_indices
    ]


def _per_sample_window(
    shap_values, sample_index: int, output_index: int, n_features: int
) -> np.ndarray:
    """Extract one sample's signed (window_size, n_features) SHAP array from a GradientExplainer result.

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
    return values.reshape(-1, n_features)


def _aggregate_feature_scores(window_values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Collapse a (window_size, n_features) signed SHAP array to one score per feature.

    Two aggregates, both over the window's time axis: `mean_signed` (mean of the raw signed
    values -- preserves direction, but timesteps that disagree in sign partially cancel) and
    `mean_abs` (mean of absolute values -- magnitude/importance regardless of direction, used
    for ranking top-k). Reporting both, rather than only one, is what lets a feature be ranked
    as important (large mean_abs) while still being honest that its net direction over the
    window was small or mixed (small mean_signed relative to mean_abs).
    """
    mean_signed = window_values.mean(axis=0)
    mean_abs = np.abs(window_values).mean(axis=0)
    return mean_signed, mean_abs


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
        window_values = _per_sample_window(shap_values, index, int(predicted_classes[index]), n_features)
        mean_signed, mean_abs = _aggregate_feature_scores(window_values)
        explanations[int(start)] = json.dumps(_top_features(mean_signed, mean_abs, feature_names, top_k))
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
        window_values = _per_sample_window(shap_values, index, 0, n_features)
        mean_signed, mean_abs = _aggregate_feature_scores(window_values)
        explanations[int(start)] = json.dumps(_top_features(mean_signed, mean_abs, feature_names, top_k))
    return explanations
