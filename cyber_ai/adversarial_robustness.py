"""6.4 -- Can real attack traffic be reshaped to slip under the Autoencoder's anomaly threshold?

A research script; production code is not touched.  Run:  python -m cyber_ai.adversarial_robustness

Method
  Take the deployed model's held-out ATTACK windows, apply the kinds of change an attacker can make to
  their own traffic without stopping the attack from working, re-score with the frozen model, and see
  how detection degrades:

    slow down   send the same packets ``k`` times more slowly     (durations and gaps x k, rates / k)
    pad         add ``p`` bytes to every packet                    (lengths, totals and byte-rate follow)
    jitter      randomise packet timing by a fraction ``j`` of the mean gap (IAT spread and extremes widen)
    combined    all three together

  The perturbations edit the *flow features* the model consumes, keeping related features consistent
  (e.g. slowing a flow also divides its packets/s), not the packets themselves.  That is an approximation
  of what re-sending real traffic would produce -- good for asking "how fragile is the decision boundary?",
  not a substitute for re-capturing perturbed attacks in the lab.  It also ignores whether the attack
  still *works* once it is slowed or padded (a slowed flood is a weaker flood), so evasion rates here are
  upper bounds on what an attacker can achieve while still hurting the victim.

Metrics: the Autoencoder gate's detection rate (the sequential design means a window it misses is never
classified), the fused-risk detection rate (risk level not Low), and the *evasion rate* -- the share of
windows that were detected before perturbation and are missed after.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

# ---- which feature columns each perturbation edits ----------------------------------------------------

_TIME_FEATURES = [  # durations and gaps, in the units CICFlowMeter reports (microseconds): scale WITH the slow-down
    "Flow Duration",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]
_RATE_FEATURES = [  # per-second rates: scale AGAINST the slow-down
    "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s", "Fwd Avg Bulk Rate", "Bwd Avg Bulk Rate",
]
_FWD_LENGTH = ["Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Avg Fwd Segment Size"]
_BWD_LENGTH = ["Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Avg Bwd Segment Size"]
_ANY_LENGTH = ["Min Packet Length", "Max Packet Length", "Packet Length Mean", "Average Packet Size"]
_IAT_GROUPS = [  # (mean, std, max, min) of each inter-arrival-time family
    ("Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min"),
    ("Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min"),
    ("Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min"),
]


def _index(feature_names: list[str]) -> dict[str, int]:
    return {name: i for i, name in enumerate(feature_names)}


def _col(windows: np.ndarray, index: dict[str, int], name: str) -> np.ndarray | None:
    return windows[..., index[name]] if name in index else None


# ---- perturbations: pure functions, (n, window, features) -> new array ----------------------------------


def slow_down(windows: np.ndarray, feature_names: list[str], factor: float) -> np.ndarray:
    """The same packets sent `factor` times more slowly: time-like features grow, rate-like ones shrink."""
    out = np.array(windows, dtype=np.float64, copy=True)
    index = _index(feature_names)
    for name in _TIME_FEATURES:
        if name in index:
            out[..., index[name]] *= factor
    for name in _RATE_FEATURES:
        if name in index:
            out[..., index[name]] /= factor
    return out


def pad_packets(windows: np.ndarray, feature_names: list[str], extra_bytes: float) -> np.ndarray:
    """`extra_bytes` of padding on every packet, in each direction that carries packets."""
    out = np.array(windows, dtype=np.float64, copy=True)
    index = _index(feature_names)
    fwd_packets = _col(out, index, "Total Fwd Packets")
    bwd_packets = _col(out, index, "Total Backward Packets")
    old_total = None
    if "Total Length of Fwd Packets" in index and "Total Length of Bwd Packets" in index:
        old_total = out[..., index["Total Length of Fwd Packets"]] + out[..., index["Total Length of Bwd Packets"]]

    def shift(names: list[str], has_packets: np.ndarray | None) -> None:
        for name in names:
            if name in index:
                column = out[..., index[name]]
                out[..., index[name]] = column + extra_bytes * (True if has_packets is None else (has_packets > 0))

    shift(_FWD_LENGTH, fwd_packets)
    shift(_BWD_LENGTH, bwd_packets)
    shift(_ANY_LENGTH, None)
    for total, packets, subflow_bytes, subflow_packets in [
        ("Total Length of Fwd Packets", fwd_packets, "Subflow Fwd Bytes", "Subflow Fwd Packets"),
        ("Total Length of Bwd Packets", bwd_packets, "Subflow Bwd Bytes", "Subflow Bwd Packets"),
    ]:
        if total in index and packets is not None:
            out[..., index[total]] += extra_bytes * packets
        if subflow_bytes in index and subflow_packets in index:
            out[..., index[subflow_bytes]] += extra_bytes * out[..., index[subflow_packets]]

    if old_total is not None and "Flow Bytes/s" in index:
        new_total = out[..., index["Total Length of Fwd Packets"]] + out[..., index["Total Length of Bwd Packets"]]
        with np.errstate(divide="ignore", invalid="ignore"):
            ratio = np.where(old_total > 0, new_total / old_total, 1.0)  # bytes/s follows the byte total
        out[..., index["Flow Bytes/s"]] *= ratio
    return out


def add_timing_jitter(windows: np.ndarray, feature_names: list[str], jitter: float) -> np.ndarray:
    """Randomise packet timing by `jitter` x the mean gap.  Deterministic approximation of the effect on the
    gap statistics: the spread grows in quadrature, the longest gap by 3 sigma, the shortest shrinks."""
    out = np.array(windows, dtype=np.float64, copy=True)
    index = _index(feature_names)
    for mean_name, std_name, max_name, min_name in _IAT_GROUPS:
        if not all(name in index for name in (mean_name, std_name, max_name, min_name)):
            continue
        spread = jitter * out[..., index[mean_name]]
        out[..., index[std_name]] = np.sqrt(out[..., index[std_name]] ** 2 + spread ** 2)
        out[..., index[max_name]] = out[..., index[max_name]] + 3.0 * spread
        out[..., index[min_name]] = np.maximum(0.0, out[..., index[min_name]] - spread)
    return out


def combine(windows: np.ndarray, feature_names: list[str], slow: float = 1.0, pad: float = 0.0, jitter: float = 0.0) -> np.ndarray:
    out = np.array(windows, dtype=np.float64, copy=True)
    if pad:
        out = pad_packets(out, feature_names, pad)
    if jitter:
        out = add_timing_jitter(out, feature_names, jitter)
    if slow != 1.0:
        out = slow_down(out, feature_names, slow)
    return out


# The attacker's search space for the best-case ("adaptive") test: every combination of these knobs.
SEARCH_SLOW = (1, 2, 5, 10, 50, 200)
SEARCH_PAD = (0, 10, 50, 200)
SEARCH_JITTER = (0, 0.5, 1, 2)


EXPERIMENTS: list[dict] = (
    [{"name": f"slow x{k:g}", "family": "slow down", "strength": k, "slow": k} for k in (2, 5, 10, 50, 200)]
    + [{"name": f"pad +{p:g}B", "family": "pad", "strength": p, "pad": p} for p in (10, 50, 200, 500, 1000)]
    + [{"name": f"jitter {j:g}x", "family": "jitter", "strength": j, "jitter": j} for j in (0.5, 1, 2, 5)]
    + [
        {"name": "combined mild (x5, +200B, 1x)", "family": "combined", "strength": 1, "slow": 5, "pad": 200, "jitter": 1},
        {"name": "combined heavy (x50, +500B, 2x)", "family": "combined", "strength": 2, "slow": 50, "pad": 500, "jitter": 2},
    ]
)


# ---- scoring the perturbed windows ----------------------------------------------------------------------


def _scale(preprocessing: dict, windows: np.ndarray) -> np.ndarray:
    n, w, f = windows.shape
    flat = np.where(np.isfinite(windows), windows, np.nan).reshape(-1, f)  # +-inf -> missing, as at inference
    scaled = preprocessing["scaler"].transform(preprocessing["imputer"].transform(flat))
    return scaled.reshape(n, w, f).astype(np.float32)


def _autoencoder_errors(autoencoder, scaled: np.ndarray, batch: int = 1024) -> np.ndarray:
    errors = []
    for i in range(0, len(scaled), batch):
        chunk = scaled[i:i + batch]
        errors.append(np.mean(np.square(chunk - autoencoder.predict(chunk, verbose=0)), axis=(1, 2)))
    return np.concatenate(errors)


def _hybrid_detected(errors: np.ndarray, scaled: np.ndarray, classifier, preprocessing: dict) -> np.ndarray:
    from cyber_ai.hybrid_risk import compute_risk_score, normalize_anomaly_score, risk_levels_for

    flagged = errors > float(preprocessing["anomaly_threshold"])
    confidence = np.full(len(errors), np.nan)
    if flagged.any():
        confidence[flagged] = classifier.predict(scaled[flagged], verbose=0).max(axis=1)
    risk = compute_risk_score(
        normalize_anomaly_score(errors, float(preprocessing["anomaly_score_low"]), float(preprocessing["anomaly_score_high"])),
        confidence,
    )
    return risk_levels_for(risk, float(preprocessing["risk_low_threshold"]), float(preprocessing["risk_high_threshold"])) != "Low"


def _rates(errors, hybrid, baseline_ae, baseline_hybrid, threshold) -> dict:
    detected = errors > threshold
    return {
        "windows": int(len(errors)),
        "ae_detection_rate": float(detected.mean()),
        "hybrid_detection_rate": float(hybrid.mean()),
        "evaded_ae": float((baseline_ae & ~detected).sum() / baseline_ae.sum()) if baseline_ae.any() else None,
        "evaded_hybrid": float((baseline_hybrid & ~hybrid).sum() / baseline_hybrid.sum()) if baseline_hybrid.any() else None,
    }


def best_case_search(windows: np.ndarray, categories: np.ndarray, category_names: list[str], names: list[str],
                     preprocessing: dict, autoencoder, threshold: float) -> dict:
    """An adaptive attacker: for each already-detected attack window, try EVERY combination of slow-down,
    padding and jitter above and keep the one with the lowest reconstruction error. A window counts as
    evadable if any single combination pushes it under the anomaly threshold.

    This is the strongest evasion this three-knob attacker can achieve against the frozen model -- the
    per-window minimum over the whole grid -- so it bounds the earlier one-knob-at-a-time results from above."""
    combos = [(k, p, j) for k in SEARCH_SLOW for p in SEARCH_PAD for j in SEARCH_JITTER]
    best_error = np.full(len(windows), np.inf)
    best_combo = np.zeros(len(windows), dtype=int)
    for c, (k, p, j) in enumerate(combos):
        scaled = _scale(preprocessing, combine(windows, names, slow=k, pad=p, jitter=j))
        errors = _autoencoder_errors(autoencoder, scaled)
        improved = errors < best_error
        best_error[improved] = errors[improved]
        best_combo[improved] = c
    evaded = best_error <= threshold
    by_category = {}
    for class_id, name in enumerate(category_names):
        mask = categories == class_id
        if mask.any():
            by_category[name] = {"detected_windows": int(mask.sum()), "evadable": int(evaded[mask].sum()),
                                 "evadable_fraction": float(evaded[mask].mean())}
    used = {}
    for c in np.unique(best_combo[evaded]):
        k, p, j = combos[int(c)]
        used[f"slow x{k:g}, pad +{p:g}B, jitter {j:g}x"] = int((best_combo[evaded] == c).sum())
    return {
        "grid": {"slow": list(SEARCH_SLOW), "pad": list(SEARCH_PAD), "jitter": list(SEARCH_JITTER), "combinations": len(combos)},
        "detected_windows": int(len(windows)),
        "evadable": int(evaded.sum()),
        "evadable_fraction": float(evaded.mean()) if len(windows) else None,
        "by_category": by_category,
        "most_used_evasions": dict(sorted(used.items(), key=lambda kv: -kv[1])[:5]),
    }


def run(scores, preprocessing: dict, autoencoder, classifier, experiments: list[dict] = EXPERIMENTS) -> dict:
    names = list(scores.feature_names)
    threshold = float(preprocessing["anomaly_threshold"])
    attack = scores.test_category >= 0
    windows = scores.test_raw_windows[attack].astype(np.float64)
    categories = scores.test_category[attack]
    category_names = list(scores.category_names)

    # Baseline through the SAME code path -- and it must reproduce the cached deployed-model errors, otherwise
    # the perturbed results would not be comparable with the model's real behaviour.
    scaled = _scale(preprocessing, windows)
    base_errors = _autoencoder_errors(autoencoder, scaled)
    if not np.allclose(base_errors, scores.test_errors[attack], rtol=1e-3, atol=1e-6):
        raise RuntimeError("Re-scoring the unperturbed windows does not reproduce the cached errors; refusing to continue.")
    base_hybrid = _hybrid_detected(base_errors, scaled, classifier, preprocessing)
    base_ae = base_errors > threshold

    def summarise(errors: np.ndarray, hybrid: np.ndarray) -> dict:
        result = {"overall": _rates(errors, hybrid, base_ae, base_hybrid, threshold), "by_category": {}}
        for class_id, name in enumerate(category_names):
            mask = categories == class_id
            if mask.any():
                result["by_category"][name] = _rates(errors[mask], hybrid[mask], base_ae[mask], base_hybrid[mask], threshold)
        return result

    output = {"baseline": summarise(base_errors, base_hybrid), "experiments": []}
    for spec in experiments:
        perturbed = combine(windows, names, slow=spec.get("slow", 1.0), pad=spec.get("pad", 0.0), jitter=spec.get("jitter", 0.0))
        scaled_p = _scale(preprocessing, perturbed)
        errors = _autoencoder_errors(autoencoder, scaled_p)
        hybrid = _hybrid_detected(errors, scaled_p, classifier, preprocessing)
        output["experiments"].append({k: v for k, v in spec.items()} | summarise(errors, hybrid))
        print(f"  {spec['name']:<34} gate detection {(errors > threshold).mean():6.1%}   fused-risk detection {hybrid.mean():6.1%}")

    print("  best-case search over every slow x pad x jitter combination (detected windows only)...")
    detected = base_ae
    output["best_case"] = best_case_search(
        windows[detected], categories[detected], category_names, names, preprocessing, autoencoder, threshold
    )
    # what an adaptive attacker leaves detected, counted over ALL attack windows (not only the detected ones)
    total = int(len(windows))
    still_detected = int(base_ae.sum()) - output["best_case"]["evadable"]
    output["best_case"]["gate_detection_rate_unperturbed"] = float(base_ae.sum() / total)
    output["best_case"]["gate_detection_rate_adaptive_attacker"] = float(still_detected / total)
    print(f"  adaptive attacker: {output['best_case']['evadable']} of {int(base_ae.sum())} detected windows can be hidden "
          f"({output['best_case']['evadable_fraction']:.1%}); overall gate detection {base_ae.mean():.1%} -> {still_detected / total:.1%}")
    return output


def _plot(report: dict, out_path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8, 4.6))
    base = report["baseline"]["overall"]["ae_detection_rate"]
    for family, marker in [("slow down", "o"), ("pad", "s"), ("jitter", "^")]:
        rows = [e for e in report["experiments"] if e["family"] == family]
        ax.plot([e["strength"] for e in rows], [e["overall"]["ae_detection_rate"] for e in rows], marker + "-", label=family)
    ax.axhline(base, color="grey", linestyle="--", label="unperturbed")
    ax.set_xscale("log")
    ax.set_xlabel("perturbation strength (slow-down factor / padding bytes / jitter x mean gap)")
    ax.set_ylabel("share of attack windows the anomaly gate still flags")
    ax.set_ylim(0, 1.02)
    ax.legend()
    ax.set_title("Detection under attacker-side traffic shaping (held-out attack windows)")
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=140)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Adversarial robustness of the deployed detector (research script).")
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--rebuild", action="store_true")
    args = parser.parse_args()

    import joblib

    from cyber_ai.holdout import load_models, load_scores

    artifacts_dir, reports_dir = Path(args.artifacts_dir), Path(args.reports_dir)
    scores = load_scores(artifacts_dir, reports_dir / "training_metrics.json", reports_dir / ".cache" / "holdout_scores.npz",
                         data_dir=args.data_dir, rebuild=args.rebuild)
    preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")
    autoencoder, classifier = load_models(artifacts_dir)

    print("Re-scoring held-out attack windows under attacker-side perturbations...")
    report = run(scores, preprocessing, autoencoder, classifier)
    report["method"] = __doc__.split("Method")[1].split("Metrics:")[0].strip()
    (reports_dir / "adversarial_robustness.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _plot(report, reports_dir / "figures" / "adversarial_robustness.png")
    base = report["baseline"]["overall"]
    print(f"Unperturbed: gate detection {base['ae_detection_rate']:.1%}, fused-risk detection {base['hybrid_detection_rate']:.1%}")
    print(f"Wrote {reports_dir / 'adversarial_robustness.json'} and figures/adversarial_robustness.png")


if __name__ == "__main__":
    main()
