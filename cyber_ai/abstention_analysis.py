"""6.1 -- Evidence for the "Unknown" (abstain) option: does classifier confidence separate real attacks
from windows the classifier has no business labelling?

The BiLSTM is trained on attack windows ONLY, so whenever the Autoencoder flags something that is not
one of the six known attacks (a false alarm on ordinary traffic, or -- in the lab -- a tool like hping3
that resembles none of them) the classifier is still forced to name one of the six. Abstaining below a
confidence threshold lets the system say "anomalous, but I don't know what" instead.

This script measures, on the deployed model's held-out windows, what that costs and what it buys, and
which threshold the VALIDATION windows recommend (the test windows are only used to confirm it).

Run:  python -m cyber_ai.abstention_analysis
Writes reports/abstention_analysis.json and reports/figures/abstention_tradeoff.png. Changes nothing else.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

CANDIDATE_THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]


def analyse_split(errors: np.ndarray, probabilities: np.ndarray, is_attack: np.ndarray, category: np.ndarray,
                  anomaly_threshold: float, thresholds: list[float] = CANDIDATE_THRESHOLDS) -> dict:
    """Abstention trade-off on one split.

    Only windows the Autoencoder flags ever reach the classifier, so only those matter:
      * known attacks   -- flagged windows that truly are one of the six categories
      * out-of-scope    -- flagged windows that are actually BENIGN (false alarms): no correct answer exists
    """
    flagged = errors > anomaly_threshold
    confidence = probabilities.max(axis=1)
    correct = probabilities.argmax(axis=1) == category
    known = flagged & (category >= 0)
    out_of_scope = flagged & ~is_attack
    if known.sum() == 0 or out_of_scope.sum() == 0:
        raise ValueError("Need both flagged known attacks and flagged false alarms to compare them.")

    from sklearn.metrics import roc_auc_score

    both = known | out_of_scope
    rows = []
    for tau in thresholds:
        answered = known & (confidence >= tau)
        rows.append({
            "threshold": tau,
            "known_attacks_still_named": float(answered.sum() / known.sum()),
            "accuracy_of_named_attacks": float(correct[answered].mean()) if answered.any() else None,
            "false_alarms_relabelled_unknown": float((out_of_scope & (confidence < tau)).sum() / out_of_scope.sum()),
            "known_attacks_relabelled_unknown": float((known & (confidence < tau)).sum() / known.sum()),
        })
    return {
        "flagged_windows": int(flagged.sum()),
        "known_attack_windows": int(known.sum()),
        "false_alarm_windows": int(out_of_scope.sum()),
        "auroc_confidence_separates_attacks_from_false_alarms": float(roc_auc_score(known[both], confidence[both])),
        "confidence_percentiles_known_attacks": _percentiles(confidence[known]),
        "confidence_percentiles_false_alarms": _percentiles(confidence[out_of_scope]),
        "by_threshold": rows,
    }


def _percentiles(values: np.ndarray) -> dict[str, float]:
    return {f"p{p}": float(np.percentile(values, p)) for p in (5, 25, 50, 75, 95)}


def recommend_threshold(rows: list[dict], min_named_fraction: float = 0.97, min_accuracy: float = 0.998) -> float | None:
    """The highest candidate threshold that still names >= `min_named_fraction` of real attacks while the
    attacks it does name stay >= `min_accuracy` accurate -- i.e. reject as many false alarms as possible
    without giving up detection categories. Chosen on VALIDATION rows only."""
    acceptable = [
        row["threshold"] for row in rows
        if row["known_attacks_still_named"] >= min_named_fraction
        and (row["accuracy_of_named_attacks"] or 0.0) >= min_accuracy
    ]
    return max(acceptable) if acceptable else None


def _plot(report: dict, out_path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = report["test"]["by_threshold"]
    taus = [r["threshold"] for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4.4))
    ax.plot(taus, [r["false_alarms_relabelled_unknown"] for r in rows], "o-", color="#2e9e6b", label="false alarms relabelled Unknown (good)")
    ax.plot(taus, [r["known_attacks_relabelled_unknown"] for r in rows], "s-", color="#d1495b", label="real attacks relabelled Unknown (cost)")
    ax.plot(taus, [r["accuracy_of_named_attacks"] for r in rows], "^-", color="#3a7bd5", label="accuracy of attacks still named")
    recommended = report["recommended_threshold"]
    if recommended is not None:
        ax.axvline(recommended, color="grey", linestyle="--", label=f"recommended {recommended:g} (from validation)")
    ax.set_xlabel("confidence threshold below which the model answers \"Unknown\"")
    ax.set_ylim(0, 1.02)
    ax.set_title("Abstention trade-off (held-out test windows)")
    ax.legend(fontsize=8, loc="center left")
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=140)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Abstention (\"Unknown\") trade-off analysis (analysis only).")
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--rebuild", action="store_true")
    args = parser.parse_args()

    import joblib

    from cyber_ai.holdout import load_scores

    artifacts_dir, reports_dir = Path(args.artifacts_dir), Path(args.reports_dir)
    scores = load_scores(artifacts_dir, reports_dir / "training_metrics.json", reports_dir / ".cache" / "holdout_scores.npz",
                         data_dir=args.data_dir, rebuild=args.rebuild)
    anomaly_threshold = float(joblib.load(artifacts_dir / "preprocessing.joblib")["anomaly_threshold"])

    validation = analyse_split(scores.validation_errors, scores.validation_probs, scores.validation_is_attack,
                               scores.validation_category, anomaly_threshold)
    test = analyse_split(scores.test_errors, scores.test_probs, scores.test_is_attack, scores.test_category, anomaly_threshold)
    recommended = recommend_threshold(validation["by_threshold"])
    report = {
        "method": "Only windows the Autoencoder flags reach the classifier. 'False alarms' are flagged windows that are "
                  "actually BENIGN -- the classifier has no correct answer for them. Threshold chosen on validation, confirmed on test.",
        "recommended_threshold": recommended,
        "validation": validation,
        "test": test,
        "limits": [
            "False alarms are a proxy for unfamiliar traffic, not a substitute for genuinely novel attacks.",
            "No held-out attack CLASS was available (that needs retraining without a class); lab tool traffic (hping3/hydra) "
            "would be the natural real-world check.",
        ],
    }
    (reports_dir / "abstention_analysis.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _plot(report, reports_dir / "figures" / "abstention_tradeoff.png")

    print(f"AUROC (confidence: real attack vs false alarm): validation {validation['auroc_confidence_separates_attacks_from_false_alarms']:.4f}, "
          f"test {test['auroc_confidence_separates_attacks_from_false_alarms']:.4f}")
    print("threshold | attacks still named | accuracy of those | false alarms -> Unknown   (test)")
    for row in test["by_threshold"]:
        print(f"  {row['threshold']:<5} | {row['known_attacks_still_named']:>18.1%} | {row['accuracy_of_named_attacks']:>16.2%} | "
              f"{row['false_alarms_relabelled_unknown']:>10.1%}")
    print(f"Recommended threshold (from validation): {recommended}")


if __name__ == "__main__":
    main()
