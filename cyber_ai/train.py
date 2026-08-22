from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_class_weight

from cyber_ai.config import load_config
from cyber_ai.data import (
    ATTACK_CATEGORIES,
    ATTACK_CATEGORY_MAP,
    BENIGN_LABEL,
    NORMAL_DECISION_LABEL,
    SOURCE_COLUMN,
    benign_window_starts,
    build_window_starts_grouped,
    dataframe_to_features,
    load_cicids2017,
    map_labels_to_attack_categories,
    row_indices_from_window_starts,
    sample_window_starts_by_class,
    split_window_starts,
    unmapped_attack_labels,
    window_labels,
)
from cyber_ai.feature_selection import rank_feature_importance, select_top_k_features
from cyber_ai.hybrid_risk import (
    calibrate_anomaly_score_range,
    calibrate_risk_levels,
    compute_risk_score,
    normalize_anomaly_score,
    risk_levels_for,
)
from cyber_ai.modeling import (
    build_bilstm_classifier,
    build_sequence_autoencoder,
    classifier_probabilities,
    balanced_accuracy_threshold,
    reconstruction_errors,
    save_model_summary,
    set_global_seed,
    supervised_f1_threshold,
)
from cyber_ai.reporting import write_json
from cyber_ai.windowing import WindowSequence

# Roadmap guidance: a class with fewer than this many raw samples can't produce a
# trustworthy per-class precision/recall/F1 (too few test examples for the number to be
# stable). We keep these classes in the taxonomy (the team's six categories are fixed),
# but flag them so their metrics aren't mistaken for reliable results.
LOW_SAMPLE_THRESHOLD = 200


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the adaptive cybersecurity framework.")
    parser.add_argument("--config", default="configs/default.yaml", help="Path to YAML config.")
    parser.add_argument("--data-dir", help="Folder containing CICIDS2017 MachineLearningCVE CSV files.")
    parser.add_argument("--feedback-csv", action="append", default=[], help="Validated feedback CSV.")
    parser.add_argument("--artifacts-dir", help="Where trained models and preprocessors are saved.")
    parser.add_argument("--reports-dir", help="Where training metrics are saved.")
    parser.add_argument("--max-rows", type=int, help="Optional total row cap.")
    parser.add_argument("--max-rows-per-class", type=int, help="Balanced cap per label.")
    parser.add_argument("--use-full-dataset", action="store_true", help="Disable row caps.")
    parser.add_argument("--window-size", type=int, help="Temporal sequence length.")
    parser.add_argument("--stride", type=int, help="Window stride.")
    parser.add_argument(
        "--top-k-features",
        type=int,
        help="Rank features by Random Forest importance (train rows only) and keep only the top K.",
    )
    parser.add_argument("--epochs", type=int, help="Override both model epoch counts.")
    parser.add_argument("--autoencoder-epochs", type=int, help="Autoencoder epochs.")
    parser.add_argument("--classifier-epochs", type=int, help="BiLSTM classifier epochs.")
    parser.add_argument("--batch-size", type=int, help="Training batch size.")
    return parser.parse_args()


def _history_to_dict(history) -> dict[str, list[float]]:
    return {key: [float(item) for item in values] for key, values in history.history.items()}


def _callbacks(patience: int, monitor: str):
    if patience <= 0:
        return []
    import tensorflow as tf

    return [
        tf.keras.callbacks.EarlyStopping(
            monitor=monitor,
            patience=patience,
            restore_best_weights=True,
        )
    ]


def _resolve_config(args: argparse.Namespace) -> dict:
    config = load_config(args.config)

    if args.data_dir:
        config["data"]["data_dir"] = args.data_dir
    if args.feedback_csv:
        config["data"]["feedback_csvs"] = list(config["data"].get("feedback_csvs") or []) + args.feedback_csv
    if args.artifacts_dir:
        config["paths"]["artifacts_dir"] = args.artifacts_dir
    if args.reports_dir:
        config["paths"]["reports_dir"] = args.reports_dir
    if args.window_size:
        config["preprocessing"]["window_size"] = args.window_size
    if args.stride:
        config["preprocessing"]["stride"] = args.stride
    if args.top_k_features:
        config["preprocessing"]["top_k_features"] = args.top_k_features
    if args.batch_size:
        config["training"]["batch_size"] = args.batch_size
    if args.epochs:
        config["training"]["autoencoder_epochs"] = args.epochs
        config["training"]["classifier_epochs"] = args.epochs
    if args.autoencoder_epochs:
        config["training"]["autoencoder_epochs"] = args.autoencoder_epochs
    if args.classifier_epochs:
        config["training"]["classifier_epochs"] = args.classifier_epochs

    if args.use_full_dataset:
        config["data"]["max_rows"] = None
        config["data"]["max_rows_per_class"] = None
    else:
        if args.max_rows is not None:
            config["data"]["max_rows"] = args.max_rows
            config["data"]["max_rows_per_class"] = None
        if args.max_rows_per_class is not None:
            config["data"]["max_rows_per_class"] = args.max_rows_per_class
            config["data"]["max_rows"] = None

    return config


def main() -> None:
    args = parse_args()
    config = _resolve_config(args)

    data_config = config["data"]
    preprocessing_config = config["preprocessing"]
    training_config = config["training"]
    model_config = config["models"]
    anomaly_config = config["anomaly"]

    artifacts_dir = Path(config["paths"]["artifacts_dir"])
    models_dir = artifacts_dir / "models"
    reports_dir = Path(config["paths"]["reports_dir"])
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    random_state = int(data_config["random_state"])
    set_global_seed(random_state)

    print("Loading and cleaning CICIDS2017 traffic data...")
    df = load_cicids2017(
        data_dir=data_config["data_dir"],
        feedback_csvs=data_config.get("feedback_csvs") or [],
        random_state=random_state,
    )
    X_raw, raw_labels, feature_names = dataframe_to_features(df)
    if raw_labels is None:
        raise ValueError("Training data must contain a Label column.")

    raw_label_encoder = LabelEncoder()
    y_raw = raw_label_encoder.fit_transform(raw_labels)
    raw_class_names = [str(item) for item in raw_label_encoder.classes_]
    if BENIGN_LABEL not in raw_class_names:
        raise ValueError(f"Expected a {BENIGN_LABEL!r} class in the dataset.")
    benign_id = int(raw_label_encoder.transform([BENIGN_LABEL])[0])

    unmapped_counts = unmapped_attack_labels(raw_labels)
    if unmapped_counts:
        total_unmapped = sum(unmapped_counts.values())
        print(
            f"Warning: {total_unmapped} rows have labels outside the known BENIGN/attack "
            f"taxonomy and will be excluded from BiLSTM training/evaluation: {unmapped_counts}"
        )

    attack_categories = map_labels_to_attack_categories(raw_labels)
    attack_row_mask = np.array([category is not None for category in attack_categories], dtype=bool)
    if not attack_row_mask.any():
        raise ValueError("No attack rows are available for grouped threat classification.")

    category_encoder = LabelEncoder()
    category_encoder.fit(attack_categories[attack_row_mask])
    category_names = [str(item) for item in category_encoder.classes_]
    y_category = np.full(len(raw_labels), -1, dtype=np.int64)
    y_category[attack_row_mask] = category_encoder.transform(attack_categories[attack_row_mask])

    # A single combined label per row: BENIGN, "Unmapped", or one of the six attack
    # categories. Used both for feature-importance ranking below and for reporting exactly
    # how many rows landed in each bucket further down.
    row_taxonomy_labels = np.array(
        [
            category if category is not None else (BENIGN_LABEL if raw_label == BENIGN_LABEL else "Unmapped")
            for category, raw_label in zip(attack_categories, raw_labels)
        ],
        dtype=object,
    )

    window_size = int(preprocessing_config["window_size"])
    stride = int(preprocessing_config["stride"])
    starts = build_window_starts_grouped(df[SOURCE_COLUMN].to_numpy(), window_size, stride)
    if len(starts) == 0:
        raise ValueError("The dataset is smaller than the configured window size.")

    max_rows_per_class = data_config.get("max_rows_per_class")
    max_rows = data_config.get("max_rows")
    if max_rows_per_class is not None:
        print(f"Capping windows to {max_rows_per_class} per class (sampled at window level, not row level)...")
        window_targets = window_labels(y_raw, starts, window_size)
        starts = sample_window_starts_by_class(starts, window_targets, int(max_rows_per_class), random_state)
    elif max_rows is not None and len(starts) > max_rows:
        print(f"Capping total windows to {max_rows}...")
        rng = np.random.RandomState(random_state)
        starts = np.sort(rng.choice(starts, size=int(max_rows), replace=False))

    train_starts, validation_starts, test_starts = split_window_starts(
        starts=starts,
        y=y_raw,
        window_size=window_size,
        validation_size=float(preprocessing_config["validation_size"]),
        test_size=float(preprocessing_config["test_size"]),
        random_state=random_state,
    )

    train_rows = row_indices_from_window_starts(train_starts, window_size)

    top_k_features = preprocessing_config.get("top_k_features")
    feature_importance_ranking: list[tuple[str, float]] | None = None
    if top_k_features:
        print(f"Ranking {len(feature_names)} features by Random Forest importance (training rows only)...")
        feature_importance_ranking = rank_feature_importance(
            X_raw.iloc[train_rows],
            row_taxonomy_labels[train_rows],
            feature_names,
            random_state=random_state,
        )
        feature_names = select_top_k_features(feature_importance_ranking, int(top_k_features))
        print(f"Selected top {len(feature_names)} features: {feature_names}")
        X_raw = X_raw[feature_names]

    print("Fitting imputer and scaler on training windows...")
    imputer = SimpleImputer(strategy="median")
    scaler = StandardScaler()
    imputer.fit(X_raw.iloc[train_rows])
    scaler.fit(imputer.transform(X_raw.iloc[train_rows]))
    X = scaler.transform(imputer.transform(X_raw)).astype(np.float32)

    batch_size = int(training_config["batch_size"])
    n_features = X.shape[1]
    n_classes = len(category_names)

    ae_train_starts = benign_window_starts(y_raw, train_starts, window_size, benign_id)
    ae_validation_starts = benign_window_starts(y_raw, validation_starts, window_size, benign_id)
    if len(ae_train_starts) == 0:
        train_targets = window_labels(y_raw, train_starts, window_size)
        ae_train_starts = train_starts[train_targets == benign_id]
        print("Warning: no all-benign training windows found; using windows whose final label is BENIGN.")
    if len(ae_validation_starts) == 0:
        validation_targets = window_labels(y_raw, validation_starts, window_size)
        ae_validation_starts = validation_starts[validation_targets == benign_id]
    if len(ae_train_starts) == 0:
        raise ValueError("No benign windows are available for Autoencoder training.")

    ae_train_sequence = WindowSequence(
        X,
        starts=ae_train_starts,
        window_size=window_size,
        batch_size=batch_size,
        target_mode="autoencoder",
        shuffle=True,
    )
    ae_validation_sequence = (
        WindowSequence(
            X,
            starts=ae_validation_starts,
            window_size=window_size,
            batch_size=batch_size,
            target_mode="autoencoder",
            shuffle=False,
        )
        if len(ae_validation_starts) > 0
        else None
    )

    print("Training sequence Autoencoder anomaly detector...")
    autoencoder = build_sequence_autoencoder(
        window_size=window_size,
        n_features=n_features,
        latent_dim=int(model_config["latent_dim"]),
        lstm_units=int(model_config["autoencoder_units"]),
        dropout=float(model_config["dropout"]),
        learning_rate=float(training_config["learning_rate"]),
    )
    ae_history = autoencoder.fit(
        ae_train_sequence,
        validation_data=ae_validation_sequence,
        epochs=int(training_config["autoencoder_epochs"]),
        callbacks=_callbacks(
            int(training_config["early_stopping_patience"]),
            "val_loss" if ae_validation_sequence is not None else "loss",
        ),
        verbose=1,
    )

    train_attack_starts = train_starts[y_category[train_starts + window_size - 1] >= 0]
    validation_attack_starts = validation_starts[y_category[validation_starts + window_size - 1] >= 0]
    test_attack_starts = test_starts[y_category[test_starts + window_size - 1] >= 0]
    if len(train_attack_starts) == 0:
        raise ValueError("No attack windows are available for BiLSTM classifier training.")

    train_sequence = WindowSequence(
        X,
        y=y_category,
        starts=train_attack_starts,
        window_size=window_size,
        batch_size=batch_size,
        target_mode="label",
        shuffle=True,
    )
    validation_sequence = (
        WindowSequence(
            X,
            y=y_category,
            starts=validation_attack_starts,
            window_size=window_size,
            batch_size=batch_size,
            target_mode="label",
            shuffle=False,
        )
        if len(validation_attack_starts) > 0
        else None
    )

    train_targets = window_labels(y_category, train_attack_starts, window_size)
    classes_in_train = np.unique(train_targets)
    weights = compute_class_weight(class_weight="balanced", classes=classes_in_train, y=train_targets)
    class_weight = {int(label): float(weight) for label, weight in zip(classes_in_train, weights)}

    print("Training BiLSTM temporal threat classifier...")
    classifier = build_bilstm_classifier(
        window_size=window_size,
        n_features=n_features,
        n_classes=n_classes,
        lstm_units=int(model_config["classifier_units"]),
        dropout=float(model_config["dropout"]),
        learning_rate=float(training_config["learning_rate"]),
    )
    classifier_history = classifier.fit(
        train_sequence,
        validation_data=validation_sequence,
        epochs=int(training_config["classifier_epochs"]),
        callbacks=_callbacks(
            int(training_config["early_stopping_patience"]),
            "val_loss" if validation_sequence is not None else "loss",
        ),
        class_weight=class_weight,
        verbose=1,
    )

    print("Calibrating anomaly threshold and evaluating models...")
    threshold_strategy = str(anomaly_config.get("threshold_strategy", "supervised_f1"))
    if threshold_strategy in {"supervised_f1", "balanced_accuracy"} and len(validation_starts) > 0:
        threshold_starts = validation_starts
    else:
        threshold_starts = ae_validation_starts if len(ae_validation_starts) > 0 else ae_train_starts
    threshold_sequence = WindowSequence(
        X,
        starts=threshold_starts,
        window_size=window_size,
        batch_size=batch_size,
        target_mode="autoencoder",
        shuffle=False,
    )
    threshold_errors = reconstruction_errors(autoencoder, threshold_sequence)
    if threshold_strategy == "supervised_f1":
        threshold_targets = (window_labels(y_raw, threshold_starts, window_size) != benign_id).astype(int)
        anomaly_threshold, threshold_report = supervised_f1_threshold(
            threshold_errors,
            threshold_targets,
            fallback_quantile=float(anomaly_config["threshold_quantile"]),
        )
    elif threshold_strategy == "balanced_accuracy":
        threshold_targets = (window_labels(y_raw, threshold_starts, window_size) != benign_id).astype(int)
        anomaly_threshold, threshold_report = balanced_accuracy_threshold(
            threshold_errors,
            threshold_targets,
            fallback_quantile=float(anomaly_config["threshold_quantile"]),
        )
    else:
        anomaly_threshold = float(np.quantile(threshold_errors, float(anomaly_config["threshold_quantile"])))
        threshold_report = {
            "threshold": anomaly_threshold,
            "strategy": "benign_quantile",
            "quantile": float(anomaly_config["threshold_quantile"]),
        }

    if len(test_attack_starts) > 0:
        test_sequence = WindowSequence(
            X,
            y=y_category,
            starts=test_attack_starts,
            window_size=window_size,
            batch_size=batch_size,
            target_mode="label",
            shuffle=False,
        )
        classifier_test_targets = window_labels(y_category, test_attack_starts, window_size)
        test_probabilities = classifier_probabilities(classifier, test_sequence)
        test_predictions = test_probabilities.argmax(axis=1)
        classifier_report = classification_report(
            classifier_test_targets,
            test_predictions,
            labels=list(range(n_classes)),
            target_names=category_names,
            zero_division=0,
            output_dict=True,
        )
        classifier_accuracy = float((test_predictions == classifier_test_targets).mean())
        classifier_confusion_matrix = confusion_matrix(
            classifier_test_targets,
            test_predictions,
            labels=list(range(n_classes)),
        ).tolist()
    else:
        classifier_report = {}
        classifier_accuracy = 0.0
        classifier_confusion_matrix = []

    ae_test_sequence = WindowSequence(
        X,
        starts=test_starts,
        window_size=window_size,
        batch_size=batch_size,
        target_mode="autoencoder",
        shuffle=False,
    )
    test_errors = reconstruction_errors(autoencoder, ae_test_sequence)
    raw_test_targets = window_labels(y_raw, test_starts, window_size)
    binary_true = (raw_test_targets != benign_id).astype(int)
    binary_pred = (test_errors > anomaly_threshold).astype(int)
    anomaly_report = classification_report(
        binary_true,
        binary_pred,
        labels=[0, 1],
        target_names=["normal", "anomaly"],
        zero_division=0,
        output_dict=True,
    )

    print("Calibrating hybrid risk fusion (Autoencoder anomaly score + BiLSTM confidence)...")
    anomaly_score_low, anomaly_score_high = calibrate_anomaly_score_range(threshold_errors)

    def _fused_risk_scores(
        window_starts: np.ndarray, raw_errors: np.ndarray, is_anomaly_pred: np.ndarray
    ) -> np.ndarray:
        normalized = normalize_anomaly_score(raw_errors, anomaly_score_low, anomaly_score_high)
        class_probability = np.full(len(window_starts), np.nan, dtype=np.float64)
        flagged_starts = window_starts[is_anomaly_pred]
        if len(flagged_starts) > 0:
            flagged_sequence = WindowSequence(
                X,
                starts=flagged_starts,
                window_size=window_size,
                batch_size=batch_size,
                target_mode=None,
                shuffle=False,
            )
            flagged_probabilities = classifier_probabilities(classifier, flagged_sequence)
            class_probability[is_anomaly_pred] = flagged_probabilities.max(axis=1)
        return compute_risk_score(normalized, class_probability)

    # Calibrate Low/Medium/High thresholds on validation data only, then evaluate the fused
    # system on the held-out test set — the same train/calibrate/evaluate split discipline
    # used for the Autoencoder's own threshold above.
    validation_is_anomaly_pred = threshold_errors > anomaly_threshold
    validation_risk_scores = _fused_risk_scores(threshold_starts, threshold_errors, validation_is_anomaly_pred)
    validation_is_true_attack = (window_labels(y_raw, threshold_starts, window_size) != benign_id)
    risk_low_threshold, risk_high_threshold = calibrate_risk_levels(validation_risk_scores, validation_is_true_attack)

    test_risk_scores = _fused_risk_scores(test_starts, test_errors, binary_pred.astype(bool))
    test_risk_levels = risk_levels_for(test_risk_scores, risk_low_threshold, risk_high_threshold)
    test_flagged = test_risk_levels != "Low"
    hybrid_report = classification_report(
        binary_true,
        test_flagged.astype(int),
        labels=[0, 1],
        target_names=["normal", "suspicious_or_attack"],
        zero_division=0,
        output_dict=True,
    )
    hybrid_confusion = confusion_matrix(binary_true, test_flagged.astype(int), labels=[0, 1]).tolist()
    false_positive_rate = (
        hybrid_confusion[0][1] / sum(hybrid_confusion[0]) if sum(hybrid_confusion[0]) else 0.0
    )
    false_negative_rate = (
        hybrid_confusion[1][0] / sum(hybrid_confusion[1]) if sum(hybrid_confusion[1]) else 0.0
    )
    risk_level_counts = {
        level: int((test_risk_levels == level).sum()) for level in ["Low", "Medium", "High"]
    }

    preprocessing_artifact = {
        "imputer": imputer,
        "scaler": scaler,
        "label_encoder": category_encoder,
        "raw_label_encoder": raw_label_encoder,
        "feature_names": feature_names,
        "window_size": window_size,
        "stride": stride,
        "benign_label": BENIGN_LABEL,
        "normal_decision_label": NORMAL_DECISION_LABEL,
        "benign_id": benign_id,
        "anomaly_threshold": anomaly_threshold,
        "anomaly_score_low": anomaly_score_low,
        "anomaly_score_high": anomaly_score_high,
        "risk_low_threshold": risk_low_threshold,
        "risk_high_threshold": risk_high_threshold,
        "class_names": category_names,
        "raw_class_names": raw_class_names,
        "attack_category_map": {key: sorted(value) for key, value in ATTACK_CATEGORY_MAP.items()},
        "classifier_scope": "attack_windows_only",
        "config": config,
    }
    joblib.dump(preprocessing_artifact, artifacts_dir / "preprocessing.joblib")

    autoencoder.save(models_dir / "autoencoder.keras")
    classifier.save(models_dir / "bilstm_classifier.keras")
    save_model_summary(autoencoder, artifacts_dir / "autoencoder_summary.txt")
    save_model_summary(classifier, artifacts_dir / "bilstm_classifier_summary.txt")

    label_counts = {str(label): int(count) for label, count in df["Label"].value_counts().items()}
    grouped_values, grouped_counts = np.unique(row_taxonomy_labels, return_counts=True)
    category_counts = {
        str(label): int(count) for label, count in zip(grouped_values, grouped_counts)
    }

    # A class this small can't produce a trustworthy precision/recall/F1 — one or two
    # misclassified windows swings the number by tens of percentage points. Flag it loudly
    # instead of letting it sit next to well-supported classes looking equally credible.
    low_sample_categories = {
        category: count
        for category, count in category_counts.items()
        if category in ATTACK_CATEGORIES and count < LOW_SAMPLE_THRESHOLD
    }
    if low_sample_categories:
        print(
            f"Warning: these categories have fewer than {LOW_SAMPLE_THRESHOLD} raw samples "
            f"and their per-class metrics should be treated as indicative only, not reliable: "
            f"{low_sample_categories}"
        )

    metrics = {
        "data": {
            "rows": int(len(df)),
            "features": int(n_features),
            "raw_labels": label_counts,
            "grouped_labels": category_counts,
            "unmapped_labels": {str(label): int(count) for label, count in unmapped_counts.items()},
            "low_sample_categories": low_sample_categories,
            "selected_features": feature_names if feature_importance_ranking is not None else None,
            "feature_importance_ranking": (
                [{"feature": name, "importance": importance} for name, importance in feature_importance_ranking]
                if feature_importance_ranking is not None
                else None
            ),
            "windows": {
                "total": int(len(starts)),
                "train": int(len(train_starts)),
                "validation": int(len(validation_starts)),
                "test": int(len(test_starts)),
                "autoencoder_train_benign": int(len(ae_train_starts)),
                "classifier_train_attack": int(len(train_attack_starts)),
                "classifier_validation_attack": int(len(validation_attack_starts)),
                "classifier_test_attack": int(len(test_attack_starts)),
            },
        },
        "autoencoder": {
            "threshold_quantile": float(anomaly_config["threshold_quantile"]),
            "threshold_strategy": threshold_strategy,
            "threshold_report": threshold_report,
            "anomaly_threshold": anomaly_threshold,
            "classification_report": anomaly_report,
            "history": _history_to_dict(ae_history),
        },
        "bilstm_classifier": {
            "accuracy": classifier_accuracy,
            "classification_report": classifier_report,
            "confusion_matrix": classifier_confusion_matrix,
            "history": _history_to_dict(classifier_history),
        },
        "hybrid_risk": {
            "anomaly_score_low": anomaly_score_low,
            "anomaly_score_high": anomaly_score_high,
            "risk_low_threshold": risk_low_threshold,
            "risk_high_threshold": risk_high_threshold,
            "risk_level_counts": risk_level_counts,
            "classification_report": hybrid_report,
            "confusion_matrix": hybrid_confusion,
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": false_negative_rate,
        },
    }
    write_json(reports_dir / "training_metrics.json", metrics)

    print(f"Saved artifacts to {artifacts_dir.resolve()}")
    print(f"Saved metrics to {(reports_dir / 'training_metrics.json').resolve()}")
    print(f"BiLSTM grouped-category test accuracy: {classifier_accuracy:.4f}")
    print(f"Autoencoder anomaly threshold: {anomaly_threshold:.6f}")
    print(
        f"Hybrid risk fusion: {risk_level_counts} "
        f"(FPR={false_positive_rate:.4f}, FNR={false_negative_rate:.4f})"
    )


if __name__ == "__main__":
    main()
