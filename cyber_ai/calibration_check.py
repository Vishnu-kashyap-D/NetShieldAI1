"""6.3 -- Is the classifier's confidence honest?  ("99.99% confident" -- is it right ~99.99% of the time?)

An analysis of the DEPLOYED model on its held-out test windows. It changes nothing in production:
it reads `artifacts/` and the dataset, writes `reports/calibration.json` and a reliability diagram.

Run:  python -m cyber_ai.calibration_check

What is measured
  1. BiLSTM classifier calibration -- on the same test windows the trainer reported accuracy on
     (attack windows only; the classifier is never asked about benign traffic in training):
     accuracy vs mean confidence, Expected/Maximum Calibration Error, Brier score, log-loss, a
     reliability table (with a dedicated look at the 99% / 99.9% / 99.99% top end, with Wilson 95%
     intervals), per-class calibration, and whether simple temperature scaling -- fitted on the
     VALIDATION windows, scored on the test windows -- would fix it.
  2. Fused risk score -- what fraction of Low / Medium / High windows really are attacks
     (a risk level is not a probability; this says what it is in practice).
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np

EPS = 1e-12


# ---------------------------------------------------------------------------------------------------
# Pure metric functions (no TensorFlow, unit-tested in backend/tests/test_calibration_metrics.py)
# ---------------------------------------------------------------------------------------------------


def confidence_and_correct(probabilities: np.ndarray, targets: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """(max probability, whether argmax == the true class) for each row."""
    probabilities = np.asarray(probabilities, dtype=np.float64)
    return probabilities.max(axis=1), probabilities.argmax(axis=1) == np.asarray(targets)


def reliability_bins(confidence: np.ndarray, correct: np.ndarray, edges: np.ndarray) -> list[dict]:
    """Group predictions by confidence into [edges[i], edges[i+1]) bins (last bin is closed on the right)."""
    confidence = np.asarray(confidence, dtype=np.float64)
    correct = np.asarray(correct, dtype=bool)
    rows = []
    for i in range(len(edges) - 1):
        low, high = float(edges[i]), float(edges[i + 1])
        last = i == len(edges) - 2
        mask = (confidence >= low) & ((confidence <= high) if last else (confidence < high))
        count = int(mask.sum())
        if count == 0:
            rows.append({"low": low, "high": high, "count": 0, "mean_confidence": None, "accuracy": None, "gap": None,
                         "wilson_low": None, "wilson_high": None})
            continue
        accuracy = float(correct[mask].mean())
        mean_conf = float(confidence[mask].mean())
        lo, hi = wilson_interval(int(correct[mask].sum()), count)
        rows.append({"low": low, "high": high, "count": count, "mean_confidence": mean_conf, "accuracy": accuracy,
                     "gap": mean_conf - accuracy, "wilson_low": lo, "wilson_high": hi})
    return rows


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion -- honest for small n and for values near 0 or 1."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return (max(0.0, centre - half), min(1.0, centre + half))


def expected_calibration_error(confidence: np.ndarray, correct: np.ndarray, n_bins: int = 15) -> float:
    """ECE with equal-width bins: sample-weighted mean |accuracy - confidence|."""
    rows = reliability_bins(confidence, correct, np.linspace(0.0, 1.0, n_bins + 1))
    total = sum(row["count"] for row in rows)
    if total == 0:
        return 0.0
    return float(sum(row["count"] * abs(row["gap"]) for row in rows if row["count"]) / total)


def maximum_calibration_error(confidence: np.ndarray, correct: np.ndarray, n_bins: int = 15, min_count: int = 10) -> float:
    """Worst bin gap, ignoring bins too small to mean anything."""
    rows = reliability_bins(confidence, correct, np.linspace(0.0, 1.0, n_bins + 1))
    gaps = [abs(row["gap"]) for row in rows if row["count"] >= min_count]
    return float(max(gaps)) if gaps else 0.0


def brier_multiclass(probabilities: np.ndarray, targets: np.ndarray) -> float:
    """Mean over rows of the squared distance between the probability vector and the one-hot truth."""
    probabilities = np.asarray(probabilities, dtype=np.float64)
    onehot = np.zeros_like(probabilities)
    onehot[np.arange(len(targets)), np.asarray(targets)] = 1.0
    return float(np.mean(np.sum((probabilities - onehot) ** 2, axis=1)))


def log_loss(probabilities: np.ndarray, targets: np.ndarray) -> float:
    probabilities = np.clip(np.asarray(probabilities, dtype=np.float64), EPS, 1.0)
    return float(-np.mean(np.log(probabilities[np.arange(len(targets)), np.asarray(targets)])))


def apply_temperature(probabilities: np.ndarray, temperature: float) -> np.ndarray:
    """Temperature-scale a softmax output: p_i^(1/T), renormalised (identical to scaling the logits by 1/T)."""
    logits = np.log(np.clip(np.asarray(probabilities, dtype=np.float64), EPS, 1.0)) / temperature
    logits -= logits.max(axis=1, keepdims=True)
    scaled = np.exp(logits)
    return scaled / scaled.sum(axis=1, keepdims=True)


def fit_temperature(probabilities: np.ndarray, targets: np.ndarray) -> float:
    """The single temperature T > 0 that minimises log-loss on the given (validation) rows."""
    from scipy.optimize import minimize_scalar

    result = minimize_scalar(
        lambda t: log_loss(apply_temperature(probabilities, t), targets), bounds=(0.05, 20.0), method="bounded"
    )
    return float(result.x)


# ---------------------------------------------------------------------------------------------------
# The analysis
# ---------------------------------------------------------------------------------------------------

TOP_END_EDGES = np.array([0.0, 0.5, 0.8, 0.9, 0.99, 0.999, 0.9999, 1.0000001])


def _calibration_summary(probabilities: np.ndarray, targets: np.ndarray) -> dict:
    confidence, correct = confidence_and_correct(probabilities, targets)
    return {
        "windows": int(len(targets)),
        "accuracy": float(correct.mean()),
        "mean_confidence": float(confidence.mean()),
        "ece": expected_calibration_error(confidence, correct),
        "mce": maximum_calibration_error(confidence, correct),
        "brier": brier_multiclass(probabilities, targets),
        "log_loss": log_loss(probabilities, targets),
    }


def analyse_classifier(scores, category_names: list[str]) -> dict:
    """Calibration of the BiLSTM on held-out attack windows, plus a temperature-scaling what-if."""
    test_mask = scores.test_category >= 0
    val_mask = scores.validation_category >= 0
    test_probs, test_targets = scores.test_probs[test_mask], scores.test_category[test_mask]
    val_probs, val_targets = scores.validation_probs[val_mask], scores.validation_category[val_mask]

    confidence, correct = confidence_and_correct(test_probs, test_targets)
    predicted = test_probs.argmax(axis=1)

    per_class = {}
    for class_id, name in enumerate(category_names):
        mask = predicted == class_id  # calibration of what the model SAYS is this class
        if mask.sum() == 0:
            per_class[name] = {"predicted_windows": 0}
            continue
        per_class[name] = {
            "predicted_windows": int(mask.sum()),
            "precision": float(correct[mask].mean()),
            "mean_confidence": float(confidence[mask].mean()),
            "true_windows": int((test_targets == class_id).sum()),
        }

    temperature = fit_temperature(val_probs, val_targets)
    scaled = apply_temperature(test_probs, temperature)
    top_end = reliability_bins(confidence, correct, TOP_END_EDGES)

    return {
        "note": "Attack windows only -- the same test windows the trainer reported classifier accuracy on.",
        "as_deployed": _calibration_summary(test_probs, test_targets),
        "reliability_bins": reliability_bins(confidence, correct, np.linspace(0.0, 1.0, 11)),
        "top_end": top_end,
        "per_predicted_class": per_class,
        "temperature_scaling": {
            "fitted_on": "validation attack windows",
            "temperature": temperature,
            "test_after_scaling": _calibration_summary(scaled, test_targets),
        },
        "confidence_is_informative": _confidence_vs_errors(confidence, correct),
    }


def _confidence_vs_errors(confidence: np.ndarray, correct: np.ndarray) -> dict:
    """Do the model's mistakes tend to carry lower confidence? (AUROC of confidence for 'was correct'.)"""
    wrong = ~correct
    if wrong.sum() == 0 or correct.sum() == 0:
        return {"errors": int(wrong.sum()), "auroc_confidence_predicts_correct": None}
    from sklearn.metrics import roc_auc_score

    return {
        "errors": int(wrong.sum()),
        "mean_confidence_when_right": float(confidence[correct].mean()),
        "mean_confidence_when_wrong": float(confidence[wrong].mean()),
        "auroc_confidence_predicts_correct": float(roc_auc_score(correct, confidence)),
    }


def analyse_risk_levels(scores, preprocessing: dict) -> dict:
    """What fraction of Low / Medium / High windows are really attacks?  (Fused risk, held-out test set.)"""
    from cyber_ai.hybrid_risk import compute_risk_score, normalize_anomaly_score, risk_levels_for

    threshold = float(preprocessing["anomaly_threshold"])
    errors = scores.test_errors
    flagged = errors > threshold
    class_confidence = np.full(len(errors), np.nan)
    class_confidence[flagged] = scores.test_probs[flagged].max(axis=1)
    risk = compute_risk_score(
        normalize_anomaly_score(errors, float(preprocessing["anomaly_score_low"]), float(preprocessing["anomaly_score_high"])),
        class_confidence,
    )
    levels = risk_levels_for(risk, float(preprocessing["risk_low_threshold"]), float(preprocessing["risk_high_threshold"]))
    result = {}
    for level in ["Low", "Medium", "High"]:
        mask = levels == level
        attacks = int(scores.test_is_attack[mask].sum())
        count = int(mask.sum())
        lo, hi = wilson_interval(attacks, count)
        result[level] = {
            "windows": count,
            "actually_attack": attacks,
            "attack_fraction": attacks / count if count else None,
            "wilson_low": lo,
            "wilson_high": hi,
        }
    return {
        "note": "A risk level is a band of a fused score, not a probability. This is what each band means in practice.",
        "by_level": result,
        "overall_attack_fraction_in_test_set": float(scores.test_is_attack.mean()),
    }


def _plot(report: dict, out_path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6))

    ax = axes[0]
    ax.plot([0, 1], [0, 1], "--", color="grey", label="perfectly calibrated")
    rows = [r for r in report["classifier"]["reliability_bins"] if r["count"]]
    ax.plot([r["mean_confidence"] for r in rows], [r["accuracy"] for r in rows], "o-", color="#3a7bd5", label="BiLSTM (as deployed)")
    for r in rows:
        ax.annotate(str(r["count"]), (r["mean_confidence"], r["accuracy"]), textcoords="offset points", xytext=(0, 7), fontsize=7, ha="center")
    ax.set_xlabel("stated confidence")
    ax.set_ylabel("actual accuracy")
    ax.set_title("Classifier reliability (numbers = windows in bin)")
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.02)
    ax.legend(loc="upper left")

    ax = axes[1]
    top = [r for r in report["classifier"]["top_end"] if r["count"]]
    labels = [f"{r['low']:g}-{min(r['high'], 1):g}\n(n={r['count']})" for r in top]
    accuracy = [r["accuracy"] for r in top]
    lower = [r["accuracy"] - r["wilson_low"] for r in top]
    upper = [r["wilson_high"] - r["accuracy"] for r in top]
    ax.bar(range(len(top)), accuracy, yerr=[lower, upper], color="#3a7bd5", capsize=3)
    ax.plot(range(len(top)), [r["mean_confidence"] for r in top], "kx", label="stated confidence")
    ax.set_xticks(range(len(top)))
    ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylim(0.0, 1.05)
    ax.set_title("Accuracy by confidence band (95% Wilson intervals)")
    ax.legend(loc="lower right")

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=140)
    plt.close(fig)


def build_report(scores, preprocessing: dict) -> dict:
    return {
        "classifier": analyse_classifier(scores, list(scores.category_names)),
        "risk_levels": analyse_risk_levels(scores, preprocessing),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Calibration check of the deployed classifier (analysis only).")
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--rebuild", action="store_true", help="Ignore the cached held-out scores and recompute them.")
    args = parser.parse_args()

    import joblib

    from cyber_ai.holdout import load_scores

    artifacts_dir, reports_dir = Path(args.artifacts_dir), Path(args.reports_dir)
    scores = load_scores(
        artifacts_dir, reports_dir / "training_metrics.json", reports_dir / ".cache" / "holdout_scores.npz",
        data_dir=args.data_dir, rebuild=args.rebuild,
    )
    preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")
    report = build_report(scores, preprocessing)

    (reports_dir / "calibration.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _plot(report, reports_dir / "figures" / "calibration_reliability.png")

    deployed = report["classifier"]["as_deployed"]
    scaled = report["classifier"]["temperature_scaling"]
    print(f"Classifier on {deployed['windows']} held-out attack windows:")
    print(f"  accuracy {deployed['accuracy']:.4f}  mean confidence {deployed['mean_confidence']:.4f}  "
          f"ECE {deployed['ece']:.4f}  Brier {deployed['brier']:.4f}  log-loss {deployed['log_loss']:.4f}")
    print("  top end (confidence band -> actual accuracy):")
    for row in report["classifier"]["top_end"]:
        if row["count"]:
            print(f"    {row['low']:<7g}-{min(row['high'], 1):<7g} n={row['count']:<6} accuracy {row['accuracy']:.4f} "
                  f"(95% CI {row['wilson_low']:.4f}-{row['wilson_high']:.4f})")
    after = scaled["test_after_scaling"]
    print(f"  temperature scaling T={scaled['temperature']:.2f}: ECE {after['ece']:.4f}, log-loss {after['log_loss']:.4f}")
    print("Risk levels -> share of windows that are truly attacks:")
    for level, row in report["risk_levels"]["by_level"].items():
        if row["windows"]:
            print(f"  {level:<6} {row['windows']:>6} windows, {row['attack_fraction']:.1%} attacks")
    print(f"Wrote {reports_dir / 'calibration.json'} and {reports_dir / 'figures' / 'calibration_reliability.png'}")


if __name__ == "__main__":
    main()
