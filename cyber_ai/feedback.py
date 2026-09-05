from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import joblib
import pandas as pd

from cyber_ai.data import BENIGN_LABEL, LABEL_COLUMN, NORMAL_DECISION_LABEL, normalize_label


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Store analyst-validated alerts for retraining.")
    parser.add_argument("--alerts-csv", required=True, help="Alert CSV produced by cyber_ai.predict.")
    parser.add_argument("--artifacts-dir", default="artifacts", help="Directory containing preprocessing.joblib.")
    parser.add_argument("--validated-label-column", default="validated_label", help="Column containing analyst labels.")
    parser.add_argument("--feedback-store", default="data/feedback/validated_traffic.csv", help="Feedback CSV path.")
    parser.add_argument("--retrain", action="store_true", help="Retrain after writing feedback.")
    parser.add_argument("--config", default="configs/default.yaml", help="Training config for retraining.")
    return parser.parse_args()


def feedback_label(value: object) -> str:
    """Maps an analyst-facing validated label onto the raw label vocabulary the model trains on.

    "Normal" (the decision label shown in the UI/alerts) and its "Normal / Ignored" variant both
    mean "this was correctly-identified benign traffic" -- the model itself was never trained on
    a literal "Normal" class, only BENIGN, so both must resolve to BENIGN before being written to
    the feedback store. Public (not `_feedback_label`) because backend/app/routers/feedback.py
    imports this directly instead of keeping its own separate copy of this mapping.
    """
    label = normalize_label(value)
    if label in {NORMAL_DECISION_LABEL, "Normal / Ignored"}:
        return BENIGN_LABEL
    return label


def main() -> None:
    args = parse_args()
    preprocessing = joblib.load(Path(args.artifacts_dir) / "preprocessing.joblib")
    feature_names = preprocessing["feature_names"]

    alerts = pd.read_csv(args.alerts_csv, low_memory=False)
    if args.validated_label_column not in alerts.columns:
        raise ValueError(
            f"Add a {args.validated_label_column!r} column with analyst-approved labels before feedback ingestion."
        )

    labels = alerts[args.validated_label_column].astype(str).str.strip()
    validated = alerts[labels.ne("") & labels.str.lower().ne("nan")].copy()
    if validated.empty:
        raise ValueError("No validated labels were found in the alert CSV.")

    feedback = validated.reindex(columns=feature_names)
    feedback[LABEL_COLUMN] = validated[args.validated_label_column].map(feedback_label)

    store_path = Path(args.feedback_store)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    if store_path.exists():
        existing = pd.read_csv(store_path, low_memory=False)
        feedback = pd.concat([existing, feedback], axis=0, ignore_index=True)
    feedback.to_csv(store_path, index=False)

    print(f"Stored {len(validated)} validated rows in {store_path.resolve()}")

    if args.retrain:
        command = [
            sys.executable,
            "-m",
            "cyber_ai.train",
            "--config",
            args.config,
            "--feedback-csv",
            str(store_path),
            "--artifacts-dir",
            args.artifacts_dir,
        ]
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
