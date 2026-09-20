"""6.5 -- Concept-drift monitoring: is live traffic still scoring the way the validation traffic did?

The risk thresholds were calibrated on the validation windows' anomaly scores. If the network's normal
behaviour changes (new software, a new service, a different time of day), "normal" traffic starts
scoring differently, false alarms and misses shift, and nothing in the model says so. This module gives
the model a cheap, model-agnostic tripwire:

  * At training time, describe the *quiet* end of the score distribution -- benign validation windows the
    Autoencoder did NOT flag -- as a fixed set of bins (`build_reference`, saved as
    `artifacts/drift_reference.json`).
  * At ingest time, drop each scored window into those bins and keep only the counts
    (`bin_scores`), so drift can be judged over ALL windows, not just the Medium/High ones that get stored.
  * On demand, compare the live bin proportions with the reference using the Population Stability Index
    (`assess`). PSI < 0.1 is stable, 0.1-0.25 "watch", > 0.25 "drifting" (the usual industry rule of thumb).

Why the quiet end only: a burst of real attacks legitimately pushes many windows over the anomaly
threshold; that is an alert-rate change, not a change in what *normal* looks like. Comparing only the
windows below the threshold isolates the second thing, which is what erodes a model silently. The alert
rate is reported alongside, for context, not folded into the status.

Pure numpy; no TensorFlow. Run `python -m cyber_ai.drift` to (re)build the reference for the current
artifacts from the held-out validation windows.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

REFERENCE_FILENAME = "drift_reference.json"
N_QUANTILE_BINS = 10
MIN_REFERENCE_WINDOWS = 200      # fewer benign quiet windows than this can't describe a distribution
MIN_LIVE_WINDOWS = 200           # fewer live quiet windows than this: PSI is mostly sampling noise
PSI_WATCH = 0.10
PSI_DRIFTING = 0.25
_EPS = 1e-4


def build_reference(errors: np.ndarray, is_benign: np.ndarray, anomaly_threshold: float) -> dict | None:
    """Describe the quiet end of the score distribution from validation windows.

    `errors` are Autoencoder reconstruction errors, `is_benign` marks windows whose true label is BENIGN.
    Returns None when there are too few benign, unflagged windows to describe anything.
    """
    errors = np.asarray(errors, dtype=np.float64)
    is_benign = np.asarray(is_benign, dtype=bool)
    quiet = errors[is_benign & (errors <= anomaly_threshold)]
    if len(quiet) < MIN_REFERENCE_WINDOWS:
        return None

    edges = np.unique(np.quantile(quiet, np.linspace(0, 1, N_QUANTILE_BINS + 1)[1:-1]))
    counts = np.bincount(np.searchsorted(edges, quiet, side="right"), minlength=len(edges) + 1)
    benign = errors[is_benign]
    return {
        "anomaly_threshold": float(anomaly_threshold),
        "bin_edges": [float(edge) for edge in edges],
        "expected_proportions": [float(c) for c in counts / counts.sum()],
        "reference_windows": int(len(quiet)),
        "benign_flag_rate": float((benign > anomaly_threshold).mean()),
        "note": "Quiet = benign validation windows the Autoencoder did not flag. Bins are quantiles of their scores.",
    }


def reference_id(reference: dict) -> str:
    """Short fingerprint of a reference: stored beside each ingest's counts so counts binned under an
    earlier model's reference are never compared with a newer one's."""
    payload = json.dumps({"t": reference["anomaly_threshold"], "e": reference["bin_edges"]}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def bin_scores(errors: np.ndarray, reference: dict) -> dict:
    """Drop live windows into the reference's bins. Returns {quiet_bin_counts, quiet_windows, flagged_windows}."""
    errors = np.asarray(errors, dtype=np.float64)
    threshold = reference["anomaly_threshold"]
    quiet = errors[errors <= threshold]
    counts = np.bincount(
        np.searchsorted(np.asarray(reference["bin_edges"]), quiet, side="right"),
        minlength=len(reference["bin_edges"]) + 1,
    )
    return {
        "quiet_bin_counts": [int(c) for c in counts],
        "quiet_windows": int(len(quiet)),
        "flagged_windows": int((errors > threshold).sum()),
    }


def psi(expected: np.ndarray, actual_counts: np.ndarray) -> float:
    """Population Stability Index between reference proportions and live bin counts."""
    expected = np.clip(np.asarray(expected, dtype=np.float64), _EPS, None)
    counts = np.asarray(actual_counts, dtype=np.float64)
    actual = np.clip(counts / counts.sum(), _EPS, None)
    return float(np.sum((actual - expected) * np.log(actual / expected)))


def assess(reference: dict, batches: list[dict]) -> dict:
    """Judge live drift from a list of per-ingest count records (each from `bin_scores`)."""
    n_bins = len(reference["bin_edges"]) + 1
    quiet_counts = np.zeros(n_bins, dtype=np.int64)
    flagged = 0
    for batch in batches:
        quiet_counts += np.asarray(batch["quiet_bin_counts"], dtype=np.int64)
        flagged += int(batch["flagged_windows"])
    quiet_total = int(quiet_counts.sum())
    total = quiet_total + flagged
    flag_rate = flagged / total if total else None

    result = {
        "windows": total,
        "quiet_windows": quiet_total,
        "flag_rate": flag_rate,
        "reference_flag_rate": reference["benign_flag_rate"],
        # Context only (a burst of real attacks raises it legitimately): how many times the validation
        # false-alarm rate the live flag rate is.
        "flag_rate_ratio": (flag_rate / reference["benign_flag_rate"]) if flag_rate is not None and reference["benign_flag_rate"] > 0 else None,
        "psi": None,
        "bins": [],
    }
    if quiet_total < MIN_LIVE_WINDOWS:
        result["status"] = "insufficient_data"
        result["message"] = (
            f"Only {quiet_total} unflagged windows scored in this period; at least {MIN_LIVE_WINDOWS} are needed "
            "before a shift in the score distribution means anything."
        )
        return result

    value = psi(reference["expected_proportions"], quiet_counts)
    live = quiet_counts / quiet_total
    result["psi"] = value
    result["bins"] = [
        {"bin": i, "expected": float(reference["expected_proportions"][i]), "live": float(live[i])} for i in range(n_bins)
    ]
    if value >= PSI_DRIFTING:
        result["status"] = "drifting"
        result["message"] = (
            "Ordinary (unflagged) traffic now scores differently from the validation traffic the thresholds were "
            "calibrated on. Expect the false-alarm / miss balance to have moved; review recent traffic and consider "
            "retraining on it."
        )
    elif value >= PSI_WATCH:
        result["status"] = "watch"
        result["message"] = "A moderate shift in how ordinary traffic scores. Keep an eye on it; re-check after more traffic."
    else:
        result["status"] = "stable"
        result["message"] = "Ordinary traffic scores like the validation traffic the thresholds were calibrated on."
    return result


def load_reference(artifacts_dir: Path) -> dict | None:
    path = Path(artifacts_dir) / REFERENCE_FILENAME
    if not path.exists():
        return None
    try:
        reference = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    required = ("anomaly_threshold", "bin_edges", "expected_proportions", "benign_flag_rate")
    if not isinstance(reference, dict) or not all(key in reference for key in required):
        return None  # unreadable or foreign file: behave as "no reference", never crash scoring
    return reference


def main() -> None:
    parser = argparse.ArgumentParser(description="Build artifacts/drift_reference.json for the deployed model.")
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--rebuild", action="store_true", help="Recompute the held-out scores instead of using the cache.")
    args = parser.parse_args()

    import joblib

    from cyber_ai.holdout import load_scores

    artifacts_dir, reports_dir = Path(args.artifacts_dir), Path(args.reports_dir)
    scores = load_scores(artifacts_dir, reports_dir / "training_metrics.json", reports_dir / ".cache" / "holdout_scores.npz",
                         data_dir=args.data_dir, rebuild=args.rebuild)
    threshold = float(joblib.load(artifacts_dir / "preprocessing.joblib")["anomaly_threshold"])
    reference = build_reference(scores.validation_errors, ~scores.validation_is_attack, threshold)
    if reference is None:
        raise SystemExit("Too few benign, unflagged validation windows to build a drift reference.")
    (artifacts_dir / REFERENCE_FILENAME).write_text(json.dumps(reference, indent=2), encoding="utf-8")
    print(f"Wrote {artifacts_dir / REFERENCE_FILENAME}: {len(reference['bin_edges']) + 1} bins over "
          f"{reference['reference_windows']} benign quiet windows; benign flag rate {reference['benign_flag_rate']:.1%}.")


if __name__ == "__main__":
    main()
