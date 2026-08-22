from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


LABEL_COLUMN = "Label"
SOURCE_COLUMN = "source_file"
BENIGN_LABEL = "BENIGN"
NORMAL_DECISION_LABEL = "Normal"

ATTACK_CATEGORY_MAP: dict[str, set[str]] = {
    "Brute Force": {
        "FTP-Patator",
        "SSH-Patator",
        "Web Attack-Brute Force",
    },
    "Malware Traffic": {
        "Heartbleed",
        "Web Attack-XSS",
        "Web Attack-Sql Injection",
    },
    "Botnet Activity": {
        "Bot",
    },
    "Data Exfiltration": {
        "Infiltration",
    },
    "DoS / DDoS": {
        "DDoS",
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
    },
    "Port Scanning": {
        "PortScan",
    },
}
ATTACK_CATEGORIES = tuple(ATTACK_CATEGORY_MAP.keys())
RAW_LABEL_TO_ATTACK_CATEGORY = {
    raw_label: category
    for category, raw_labels in ATTACK_CATEGORY_MAP.items()
    for raw_label in raw_labels
}

LEAKAGE_COLUMNS = {
    # Destination Port is a well-documented leakage feature in CICIDS2017: this synthetic
    # testbed's attacks target fixed ports, so a model can partly "cheat" by port-matching
    # instead of learning behavioral traffic patterns. Excluded from model input.
    "Destination Port",
}

PREDICTION_METADATA_COLUMNS = {
    "window_start",
    "window_end",
    "source_file",
    "actual_label",
    "actual_category",
    "predicted_label",
    "confidence",
    "anomaly_score",
    "anomaly_threshold",
    "is_anomaly",
    "pipeline_action",
    "risk_score",
    "risk_level",
    "top_classifier_features",
    "top_anomaly_features",
    "validated_label",
}


def normalize_label(value: object) -> str:
    label = str(value).strip()
    label = label.replace("\ufffd", "-")
    label = label.replace("–", "-").replace("—", "-")
    label = re.sub(r"\s*-\s*", "-", label)
    label = re.sub(r"\s+", " ", label)
    return label


def to_attack_category(label: object) -> str | None:
    """Map a raw label to one of the project's six attack categories, or None.

    None means "not one of our known BENIGN/attack labels" — this covers both true
    benign traffic and any label this taxonomy doesn't recognize (e.g. free-text
    analyst feedback labels, or a different dataset's label vocabulary). Callers that
    need to distinguish "confirmed benign" from "unrecognized label" should check
    against BENIGN_LABEL/NORMAL_DECISION_LABEL directly, and should surface unrecognized
    labels via `unmapped_attack_labels` rather than assume they're safe to drop silently.
    """
    normalized = normalize_label(label)
    if normalized in {BENIGN_LABEL, NORMAL_DECISION_LABEL, "Normal / Ignored"}:
        return None
    if normalized in ATTACK_CATEGORIES:
        return normalized
    return RAW_LABEL_TO_ATTACK_CATEGORY.get(normalized)


def map_labels_to_attack_categories(labels: np.ndarray) -> np.ndarray:
    return np.array([to_attack_category(label) for label in labels], dtype=object)


def unmapped_attack_labels(labels: np.ndarray) -> dict[str, int]:
    """Count occurrences of labels that are neither BENIGN nor a known attack category.

    A non-empty result means some rows are being silently excluded from BiLSTM
    training/evaluation (they're too ambiguous to categorize) — this should be surfaced
    to a human, not swallowed. Expect this to be non-empty when scoring analyst feedback
    CSVs (free-text labels) or an external dataset with a different label vocabulary
    (e.g. UNSW-NB15), even when it's empty for clean CICIDS2017 data.
    """
    counts: dict[str, int] = {}
    for label in labels:
        normalized = normalize_label(label)
        if normalized in {BENIGN_LABEL, NORMAL_DECISION_LABEL, "Normal / Ignored"}:
            continue
        if normalized in ATTACK_CATEGORIES or normalized in RAW_LABEL_TO_ATTACK_CATEGORY:
            continue
        counts[normalized] = counts.get(normalized, 0) + 1
    return counts


def _base_column_name(column: str) -> str:
    return re.sub(r"\.\d+$", "", str(column).strip())


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    normalized_columns = [_base_column_name(column) for column in df.columns]

    keep_positions: list[int] = []
    final_columns: list[str] = []
    seen: set[str] = set()
    label_seen = False
    for position, column in enumerate(normalized_columns):
        if column == LABEL_COLUMN:
            if label_seen:
                continue
            label_seen = True
            keep_positions.append(position)
            final_columns.append(column)
            continue
        if column in seen:
            continue
        seen.add(column)
        keep_positions.append(position)
        final_columns.append(column)

    cleaned = df.iloc[:, keep_positions].copy()
    cleaned.columns = final_columns
    return cleaned


def clean_raw_dataframe(df: pd.DataFrame, source_name: str | None = None) -> pd.DataFrame:
    cleaned = normalize_columns(df)
    if LABEL_COLUMN in cleaned.columns:
        cleaned[LABEL_COLUMN] = cleaned[LABEL_COLUMN].map(normalize_label)
        cleaned = cleaned[cleaned[LABEL_COLUMN].notna()]
        cleaned = cleaned[cleaned[LABEL_COLUMN].astype(str).str.len() > 0]
    if source_name is not None:
        cleaned[SOURCE_COLUMN] = source_name
    return cleaned


def load_cicids2017(
    data_dir: str | Path,
    feedback_csvs: Iterable[str | Path] | None = None,
    random_state: int = 42,
) -> pd.DataFrame:
    """Load and clean all CICIDS2017 CSVs, preserving per-file row order and contiguity.

    Row-level subsampling (max_rows / max_rows_per_class) is intentionally NOT done here.
    Dropping rows here would leave gaps in the timeline, so a later "10-row window" would
    silently splice together rows that were never temporally adjacent in the real capture.
    Any row-count cap must instead be applied at the window level, after
    `build_window_starts_grouped` has built windows that respect per-file boundaries — see
    `sample_window_starts_by_class`.
    """
    data_path = Path(data_dir)
    csv_files = sorted(data_path.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_path.resolve()}")

    frames: list[pd.DataFrame] = []
    for csv_file in csv_files:
        frame = pd.read_csv(csv_file, low_memory=False)
        frames.append(clean_raw_dataframe(frame, source_name=csv_file.name))

    for feedback_csv in feedback_csvs or []:
        feedback_path = Path(feedback_csv)
        if feedback_path.exists():
            frame = pd.read_csv(feedback_path, low_memory=False)
            frames.append(clean_raw_dataframe(frame, source_name=feedback_path.name))

    combined = pd.concat(frames, axis=0, ignore_index=True)
    combined = combined.replace([np.inf, -np.inf], np.nan)

    # CICIDS2017 is documented to contain a large number of exact-duplicate flow records
    # (a known artifact of the capture tooling, not a modeling signal). Left in, identical
    # rows can end up split across train and test, letting the model "recognize" a test row
    # it already memorized rather than generalize. Dropped here, before windowing, so the
    # remaining rows within each file are still the correct definition of "contiguous."
    dedup_columns = [column for column in combined.columns if column != SOURCE_COLUMN]
    rows_before = len(combined)
    combined = combined.drop_duplicates(subset=dedup_columns, keep="first")
    duplicates_dropped = rows_before - len(combined)
    if duplicates_dropped:
        print(
            f"Dropped {duplicates_dropped} exact-duplicate rows "
            f"({duplicates_dropped / rows_before:.1%} of loaded data)."
        )

    return combined.reset_index(drop=True)


def infer_feature_columns(df: pd.DataFrame) -> list[str]:
    excluded = set(PREDICTION_METADATA_COLUMNS) | LEAKAGE_COLUMNS | {LABEL_COLUMN, SOURCE_COLUMN}
    return [column for column in df.columns if column not in excluded]


def dataframe_to_features(
    df: pd.DataFrame,
    feature_names: list[str] | None = None,
) -> tuple[pd.DataFrame, np.ndarray | None, list[str]]:
    features = feature_names or infer_feature_columns(df)
    aligned = df.reindex(columns=features)
    aligned = aligned.apply(pd.to_numeric, errors="coerce")
    aligned = aligned.replace([np.inf, -np.inf], np.nan)

    labels = None
    if LABEL_COLUMN in df.columns:
        labels = df[LABEL_COLUMN].map(normalize_label).to_numpy()

    return aligned, labels, features


def build_window_starts(row_count: int, window_size: int, stride: int) -> np.ndarray:
    if row_count < window_size:
        return np.array([], dtype=np.int64)
    return np.arange(0, row_count - window_size + 1, stride, dtype=np.int64)


def build_window_starts_grouped(source_files: np.ndarray, window_size: int, stride: int) -> np.ndarray:
    """Build window starts within each contiguous run of the same source_file only.

    Rows from different CICIDS2017 capture days are simply concatenated one after another,
    so a plain `build_window_starts(len(X), ...)` can produce a window whose first few rows
    come from the end of one day's CSV and whose last rows come from the start of the next
    day's CSV. Grouping by contiguous source_file blocks first prevents that.
    """
    source_files = np.asarray(source_files)
    if len(source_files) == 0:
        return np.array([], dtype=np.int64)

    change_points = np.where(source_files[1:] != source_files[:-1])[0] + 1
    block_starts = np.concatenate(([0], change_points))
    block_ends = np.concatenate((change_points, [len(source_files)]))

    all_starts: list[np.ndarray] = []
    for block_start, block_end in zip(block_starts, block_ends):
        local_starts = build_window_starts(int(block_end - block_start), window_size, stride)
        all_starts.append(local_starts + block_start)
    return np.concatenate(all_starts) if all_starts else np.array([], dtype=np.int64)


def sample_window_starts_by_class(
    starts: np.ndarray,
    labels_for_starts: np.ndarray,
    max_per_class: int,
    random_state: int,
) -> np.ndarray:
    """Cap the number of windows per class, sampling whole windows instead of raw rows.

    Subsampling rows before windowing leaves gaps in the timeline (see `load_cicids2017`);
    subsampling already-built windows keeps every window's rows genuinely contiguous.
    """
    rng = np.random.RandomState(random_state)
    sampled: list[np.ndarray] = []
    for label in np.unique(labels_for_starts):
        label_starts = starts[labels_for_starts == label]
        if len(label_starts) > max_per_class:
            chosen = rng.choice(label_starts, size=max_per_class, replace=False)
        else:
            chosen = label_starts
        sampled.append(chosen)
    combined = np.concatenate(sampled) if sampled else np.array([], dtype=np.int64)
    return np.sort(combined)


def window_labels(y: np.ndarray, starts: np.ndarray, window_size: int) -> np.ndarray:
    return y[starts + window_size - 1]


def _can_stratify(targets: np.ndarray, split_size: float) -> bool:
    if len(targets) < 2:
        return False
    _, counts = np.unique(targets, return_counts=True)
    requested = int(round(len(targets) * split_size))
    return counts.min() >= 2 and requested >= len(counts)


def split_window_starts(
    starts: np.ndarray,
    y: np.ndarray,
    window_size: int,
    validation_size: float,
    test_size: float,
    random_state: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    if len(starts) < 3:
        raise ValueError("Not enough windows to create train/validation/test splits.")

    targets = window_labels(y, starts, window_size)
    stratify = targets if _can_stratify(targets, test_size) else None

    train_val_starts, test_starts, train_val_targets, _ = train_test_split(
        starts,
        targets,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )

    relative_validation_size = validation_size / max(1e-9, 1.0 - test_size)
    stratify_train_val = (
        train_val_targets if _can_stratify(train_val_targets, relative_validation_size) else None
    )

    train_starts, validation_starts = train_test_split(
        train_val_starts,
        test_size=relative_validation_size,
        random_state=random_state,
        stratify=stratify_train_val,
    )

    return (
        np.asarray(train_starts, dtype=np.int64),
        np.asarray(validation_starts, dtype=np.int64),
        np.asarray(test_starts, dtype=np.int64),
    )


def benign_window_starts(
    y: np.ndarray,
    starts: np.ndarray,
    window_size: int,
    benign_id: int,
) -> np.ndarray:
    if len(starts) == 0:
        return np.array([], dtype=np.int64)
    benign_mask = (y == benign_id).astype(np.int16)
    rolling_benign = np.convolve(
        benign_mask,
        np.ones(window_size, dtype=np.int16),
        mode="valid",
    )
    return starts[rolling_benign[starts] == window_size]


def row_indices_from_window_starts(
    starts: np.ndarray,
    window_size: int,
    max_expanded_indices: int = 5_000_000,
) -> np.ndarray:
    if len(starts) == 0:
        return np.array([], dtype=np.int64)
    if len(starts) * window_size > max_expanded_indices:
        return np.unique(starts + window_size - 1)
    offsets = np.arange(window_size, dtype=np.int64)
    return np.unique((starts[:, None] + offsets[None, :]).ravel())
