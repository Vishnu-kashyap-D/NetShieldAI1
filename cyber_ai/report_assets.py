from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.metrics import auc, roc_curve
from sklearn.preprocessing import label_binarize

from cyber_ai.data import (
    BENIGN_LABEL,
    SOURCE_COLUMN,
    build_window_starts_grouped,
    dataframe_to_features,
    load_cicids2017,
    map_labels_to_attack_categories,
    sample_window_starts_by_class,
    split_window_starts,
    window_labels,
)
from cyber_ai.modeling import classifier_probabilities, reconstruction_errors
from cyber_ai.windowing import WindowSequence


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate report figures (confusion matrix, ROC curves, reconstruction "
        "error distribution, per-class metrics table, latency histogram) from trained artifacts."
    )
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--figures-dir", default="reports/figures")
    return parser.parse_args()


def _rebuild_test_split(preprocessing: dict):
    """Reconstruct the exact test-window split train.py used, from the same stored config
    and random_state — deterministic, so this reproduces the identical held-out windows
    without needing them to have been saved separately."""
    config = preprocessing["config"]
    data_config = config["data"]
    preprocessing_config = config["preprocessing"]
    random_state = int(data_config["random_state"])

    df = load_cicids2017(
        data_dir=data_config["data_dir"],
        feedback_csvs=data_config.get("feedback_csvs") or [],
        random_state=random_state,
    )
    feature_names = preprocessing["feature_names"]
    X_raw, raw_labels, _ = dataframe_to_features(df, feature_names=feature_names)

    raw_label_encoder = preprocessing["raw_label_encoder"]
    y_raw = raw_label_encoder.transform(raw_labels)
    benign_id = int(preprocessing["benign_id"])

    category_encoder = preprocessing["label_encoder"]
    attack_categories = map_labels_to_attack_categories(raw_labels)
    attack_row_mask = np.array([category is not None for category in attack_categories], dtype=bool)
    y_category = np.full(len(raw_labels), -1, dtype=np.int64)
    y_category[attack_row_mask] = category_encoder.transform(attack_categories[attack_row_mask])

    window_size = int(preprocessing["window_size"])
    stride = int(preprocessing["stride"])
    starts = build_window_starts_grouped(df[SOURCE_COLUMN].to_numpy(), window_size, stride)

    max_rows_per_class = data_config.get("max_rows_per_class")
    max_rows = data_config.get("max_rows")
    if max_rows_per_class is not None:
        window_targets = window_labels(y_raw, starts, window_size)
        starts = sample_window_starts_by_class(starts, window_targets, int(max_rows_per_class), random_state)
    elif max_rows is not None and len(starts) > max_rows:
        rng = np.random.RandomState(random_state)
        starts = np.sort(rng.choice(starts, size=int(max_rows), replace=False))

    _, _, test_starts = split_window_starts(
        starts=starts,
        y=y_raw,
        window_size=window_size,
        validation_size=float(preprocessing_config["validation_size"]),
        test_size=float(preprocessing_config["test_size"]),
        random_state=random_state,
    )

    imputer = preprocessing["imputer"]
    scaler = preprocessing["scaler"]
    X = scaler.transform(imputer.transform(X_raw)).astype(np.float32)

    test_attack_starts = test_starts[y_category[test_starts + window_size - 1] >= 0]
    return {
        "X": X,
        "y_raw": y_raw,
        "y_category": y_category,
        "benign_id": benign_id,
        "test_starts": test_starts,
        "test_attack_starts": test_attack_starts,
        "window_size": window_size,
    }


def _plot_confusion_matrix(cm: np.ndarray, category_names: list[str], out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(category_names)))
    ax.set_yticks(range(len(category_names)))
    ax.set_xticklabels(category_names, rotation=45, ha="right")
    ax.set_yticklabels(category_names)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("BiLSTM Classifier — Confusion Matrix (test set)")
    threshold = cm.max() / 2 if cm.max() else 0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, str(cm[i, j]), ha="center", va="center",
                color="white" if cm[i, j] > threshold else "black", fontsize=9,
            )
    fig.colorbar(im, ax=ax, label="Window count")
    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)


def _plot_roc_curves(y_true: np.ndarray, probabilities: np.ndarray, category_names: list[str], out_path: Path) -> dict:
    n_classes = len(category_names)
    y_binarized = label_binarize(y_true, classes=list(range(n_classes)))
    fig, ax = plt.subplots(figsize=(8, 7))
    auc_scores = {}
    for class_index, name in enumerate(category_names):
        support = int(y_binarized[:, class_index].sum())
        if support == 0:
            continue  # can't plot a class with zero true positives in this test split
        fpr, tpr, _ = roc_curve(y_binarized[:, class_index], probabilities[:, class_index])
        roc_auc = auc(fpr, tpr)
        auc_scores[name] = float(roc_auc)
        ax.plot(fpr, tpr, label=f"{name} (AUC={roc_auc:.3f}, n={support})")
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Chance")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("BiLSTM Classifier — One-vs-Rest ROC Curves (test set)")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    return auc_scores


def _plot_reconstruction_error_distribution(
    errors: np.ndarray, is_attack: np.ndarray, threshold: float, out_path: Path
) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    bins = np.linspace(0, np.percentile(errors, 99), 60)
    ax.hist(errors[~is_attack], bins=bins, alpha=0.6, label="Actual BENIGN", color="#2F855A")
    ax.hist(errors[is_attack], bins=bins, alpha=0.6, label="Actual attack", color="#C53030")
    ax.axvline(threshold, color="black", linestyle="--", label=f"Anomaly threshold ({threshold:.3f})")
    ax.set_xlabel("Reconstruction error")
    ax.set_ylabel("Window count")
    ax.set_title("Autoencoder — Reconstruction Error Distribution (test set)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)


def _plot_latency_histogram(latency_report_path: Path, out_path: Path) -> bool:
    if not latency_report_path.exists():
        return False
    latency_report = json.loads(latency_report_path.read_text(encoding="utf-8"))
    raw = latency_report.get("raw_latencies_ms")
    if not raw:
        return False

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    axes[0].hist(raw["autoencoder_only"], bins=40, color="#2B6CB0")
    axes[0].set_title("Autoencoder-only latency (every window)")
    axes[0].set_xlabel("Latency (ms)")
    axes[0].set_ylabel("Window count")

    axes[1].hist(raw["full_pipeline_blended"], bins=40, color="#B7791F")
    axes[1].set_title("Full pipeline latency (blended, realistic mix)")
    axes[1].set_xlabel("Latency (ms)")

    fig.suptitle("Detection Latency Distribution")
    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    return True


def main() -> None:
    args = parse_args()
    artifacts_dir = Path(args.artifacts_dir)
    reports_dir = Path(args.reports_dir)
    figures_dir = Path(args.figures_dir)
    figures_dir.mkdir(parents=True, exist_ok=True)

    preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")
    category_encoder = preprocessing["label_encoder"]
    category_names = list(category_encoder.classes_)
    anomaly_threshold = float(preprocessing["anomaly_threshold"])

    autoencoder = tf.keras.models.load_model(artifacts_dir / "models" / "autoencoder.keras")
    classifier = tf.keras.models.load_model(artifacts_dir / "models" / "bilstm_classifier.keras")

    metrics_path = reports_dir / "training_metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

    print("1/5  Confusion matrix...")
    cm = np.array(metrics["bilstm_classifier"]["confusion_matrix"])
    _plot_confusion_matrix(cm, category_names, figures_dir / "confusion_matrix.png")

    print("2/5  Per-class metrics table...")
    report = metrics["bilstm_classifier"]["classification_report"]
    rows = []
    for name in category_names:
        if name in report:
            row = report[name]
            rows.append(
                {
                    "category": name,
                    "precision": row["precision"],
                    "recall": row["recall"],
                    "f1_score": row["f1-score"],
                    "support": row["support"],
                }
            )
    pd.DataFrame(rows).to_csv(figures_dir / "per_class_metrics.csv", index=False)

    print("Rebuilding the exact test split used for training (same config, same seed)...")
    split = _rebuild_test_split(preprocessing)
    window_size = split["window_size"]

    print("3/5  ROC curves (rescoring the classifier on the rebuilt test set)...")
    auc_scores = {}
    if len(split["test_attack_starts"]) > 0:
        test_sequence = WindowSequence(
            split["X"], starts=split["test_attack_starts"], window_size=window_size,
            batch_size=256, target_mode=None, shuffle=False,
        )
        test_probabilities = classifier_probabilities(classifier, test_sequence)
        classifier_test_targets = window_labels(split["y_category"], split["test_attack_starts"], window_size)
        auc_scores = _plot_roc_curves(
            classifier_test_targets, test_probabilities, category_names, figures_dir / "roc_curves.png"
        )
    else:
        print("  skipped — no attack windows in the rebuilt test split")

    print("4/5  Reconstruction error distribution (rescoring the Autoencoder on the test set)...")
    ae_test_sequence = WindowSequence(
        split["X"], starts=split["test_starts"], window_size=window_size,
        batch_size=256, target_mode="autoencoder", shuffle=False,
    )
    test_errors = reconstruction_errors(autoencoder, ae_test_sequence)
    raw_test_targets = window_labels(split["y_raw"], split["test_starts"], window_size)
    is_attack = raw_test_targets != split["benign_id"]
    _plot_reconstruction_error_distribution(
        test_errors, is_attack, anomaly_threshold, figures_dir / "reconstruction_error_distribution.png"
    )

    print("5/5  Latency histogram...")
    made_latency_plot = _plot_latency_histogram(
        reports_dir / "latency_benchmark.json", figures_dir / "latency_histogram.png"
    )
    if not made_latency_plot:
        print("  skipped — run cyber_ai.latency_benchmark first (needs raw_latencies_ms in the report)")

    write_summary = {
        "roc_auc_by_category": auc_scores,
        "figures_dir": str(figures_dir.resolve()),
    }
    (figures_dir / "summary.json").write_text(json.dumps(write_summary, indent=2), encoding="utf-8")

    print(f"Saved figures to {figures_dir.resolve()}")


if __name__ == "__main__":
    main()
