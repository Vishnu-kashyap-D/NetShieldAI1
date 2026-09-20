"""6.6 -- Does the cross-window layer catch what per-window alerting misses, without crying wolf?

Scores whole, time-ordered CICIDS2017 capture days with the DEPLOYED model -- every window, in order, with the
classifier run on ALL of them (the one thing the shuffled held-out split cannot provide) -- then runs the
persistence detector over each day and compares it with per-window alerting.

  * Monday is pure benign traffic: any campaign found there is a FALSE campaign.
  * On the other days, for each attack category we count the attack windows that raised NO per-window alert
    ("quiet" attack windows) and how many of them fall inside a reported campaign.
  * Every benign window inside a campaign, on any day, is counted as false coverage.

Caveat, stated up front: the model was trained on windows drawn from these same files, so absolute scores are
optimistic. The comparison between per-window alerting and the campaign layer uses the *same* scores, so the
gain it shows is fair; absolute recall is not a generalisation claim. Only some attack types are helped (see
the per-category table this prints) and that is reported as found, not smoothed over.

Run:  python -m cyber_ai.correlation_eval          (writes reports/correlation_eval.json)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from cyber_ai import correlation

# file -> what it contains (from the CICIDS2017 documentation)
DAYS = {
    "Monday-WorkingHours.pcap_ISCX.csv": "benign only",
    "Tuesday-WorkingHours.pcap_ISCX.csv": "FTP/SSH brute force",
    "Wednesday-workingHours.pcap_ISCX.csv": "DoS variants, Heartbleed",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": "web attacks",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": "botnet",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": "port scan",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": "DDoS",
}
BENIGN_FILE = "Monday-WorkingHours.pcap_ISCX.csv"


def score_day(csv_path: Path, preprocessing: dict, autoencoder, classifier) -> dict:
    """Both models' output for every window of one capture file, in time order, plus ground truth."""
    import pandas as pd

    from cyber_ai.data import BENIGN_LABEL, build_window_starts, clean_raw_dataframe, dataframe_to_features, to_attack_category
    from cyber_ai.modeling import classifier_probabilities, reconstruction_errors
    from cyber_ai.windowing import WindowSequence

    frame = clean_raw_dataframe(pd.read_csv(csv_path, low_memory=False), source_name=csv_path.name)
    frame = frame.replace([np.inf, -np.inf], np.nan)
    frame = frame.drop_duplicates(subset=[c for c in frame.columns if c != "source_file"]).reset_index(drop=True)
    X_raw, labels, _ = dataframe_to_features(frame, feature_names=list(preprocessing["feature_names"]))
    X = preprocessing["scaler"].transform(preprocessing["imputer"].transform(X_raw)).astype(np.float32)

    window, stride = int(preprocessing["window_size"]), int(preprocessing["stride"])
    starts = build_window_starts(len(X), window, stride)

    def sequence(mode):
        return WindowSequence(X, starts=starts, window_size=window, batch_size=1024, target_mode=mode, shuffle=False)

    last_label = labels[starts + window - 1]
    return {
        "starts": starts,
        "errors": reconstruction_errors(autoencoder, sequence("autoencoder")),
        "probs": classifier_probabilities(classifier, sequence(None)).astype(np.float32),   # classifier on EVERY window
        "is_attack": last_label != BENIGN_LABEL,
        "category": np.array([to_attack_category(label) or "" for label in last_label], dtype=str),
    }


def risk_scores(day: dict, preprocessing: dict) -> np.ndarray:
    """The fused per-window risk score the pipeline itself would have produced (classifier only counts when flagged)."""
    from cyber_ai.hybrid_risk import compute_risk_score, normalize_anomaly_score

    flagged = day["errors"] > float(preprocessing["anomaly_threshold"])
    confidence = np.where(flagged, day["probs"].max(axis=1), np.nan)
    return compute_risk_score(
        normalize_anomaly_score(day["errors"], float(preprocessing["anomaly_score_low"]), float(preprocessing["anomaly_score_high"])),
        confidence,
    )


def evaluate_day(day: dict, preprocessing: dict, **params) -> dict:
    window, stride = int(preprocessing["window_size"]), int(preprocessing["stride"])
    alert_floor = float(preprocessing["risk_low_threshold"])
    risk = risk_scores(day, preprocessing)
    campaigns = correlation.find_campaigns(
        day["starts"], day["probs"].argmax(axis=1), day["probs"].max(axis=1), risk, alert_floor, window, stride, **params
    )
    covered = np.zeros(len(day["starts"]), dtype=bool)
    for campaign in campaigns:
        covered[campaign.first_index:campaign.last_index + 1] = True
    alerted = risk >= alert_floor
    attack = day["is_attack"]
    quiet_attack = attack & ~alerted
    by_category = {}
    for category in sorted(set(day["category"][quiet_attack]) - {""}):
        mask = quiet_attack & (day["category"] == category)
        by_category[category] = {"quiet_attack_windows": int(mask.sum()), "recovered": int((mask & covered).sum())}
    return {
        "windows": int(len(day["starts"])),
        "attack_windows": int(attack.sum()),
        "campaigns": len(campaigns),
        "windows_in_campaigns": int(covered.sum()),
        "benign_windows_in_campaigns": int((covered & ~attack).sum()),
        "attack_windows_alerted_alone": int((attack & alerted).sum()),
        "quiet_attack_windows": int(quiet_attack.sum()),
        "quiet_attack_windows_recovered": int((quiet_attack & covered).sum()),
        "quiet_by_category": by_category,
    }


def sweep(days: dict[str, dict], preprocessing: dict, confidences=(0.9, 0.95, 0.99, 0.995), min_windows=(5, 8, 12, 20),
          max_gaps=(0, 1)) -> list[dict]:
    rows = []
    for confidence in confidences:
        for minimum in min_windows:
            for gap in max_gaps:
                params = {"min_confidence": confidence, "min_windows": minimum, "max_gap": gap}
                per_day = {name: evaluate_day(day, preprocessing, **params) for name, day in days.items()}
                benign_windows = sum(d["windows"] - d["attack_windows"] for d in per_day.values())
                quiet = sum(d["quiet_attack_windows"] for d in per_day.values())
                recovered = sum(d["quiet_attack_windows_recovered"] for d in per_day.values())
                rows.append({
                    **params,
                    "false_campaigns_on_benign_day": per_day[BENIGN_FILE]["campaigns"],
                    "false_coverage": sum(d["benign_windows_in_campaigns"] for d in per_day.values()) / benign_windows,
                    "quiet_attack_windows": quiet,
                    "quiet_attack_windows_recovered": recovered,
                    "recovery_rate": recovered / quiet if quiet else None,
                    "per_day": per_day,
                })
    return rows


def choose_defaults(rows: list[dict], max_false_coverage: float = 0.005) -> dict | None:
    """Among settings with no false campaign on the pure-benign day and false coverage under `max_false_coverage`
    of all benign windows, the one that recovers the most missed attack windows."""
    clean = [r for r in rows if r["false_campaigns_on_benign_day"] == 0 and r["false_coverage"] <= max_false_coverage]
    return max(clean, key=lambda r: (r["recovery_rate"] or 0.0, r["min_confidence"], r["min_windows"])) if clean else None


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the cross-window campaign detector on time-ordered CICIDS2017 days.")
    parser.add_argument("--artifacts-dir", default="artifacts")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--data-dir", default="MachineLearningCVE")
    parser.add_argument("--rebuild", action="store_true", help="Re-score the capture days instead of using the cache.")
    args = parser.parse_args()

    import joblib

    artifacts_dir, reports_dir, data_dir = Path(args.artifacts_dir), Path(args.reports_dir), Path(args.data_dir)
    preprocessing = joblib.load(artifacts_dir / "preprocessing.joblib")

    cache = reports_dir / ".cache" / "correlation_days_v2.npz"
    fields = ["starts", "errors", "probs", "is_attack", "category"]
    days: dict[str, dict] = {}
    if cache.exists() and not args.rebuild:
        with np.load(cache, allow_pickle=False) as stored:
            days = {name: {f: stored[f"{i}_{f}"] for f in fields} for i, name in enumerate(DAYS) if f"{i}_starts" in stored}
    if len(days) != len(DAYS):
        from cyber_ai.holdout import load_models

        autoencoder, classifier = load_models(artifacts_dir)
        days = {}
        for name in DAYS:
            print(f"Scoring {name} ...", flush=True)
            days[name] = score_day(data_dir / name, preprocessing, autoencoder, classifier)
        cache.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(cache, **{f"{i}_{f}": days[name][f] for i, name in enumerate(DAYS) for f in fields})

    rows = sweep(days, preprocessing)
    chosen = choose_defaults(rows)
    defaults = {"min_confidence": correlation.DEFAULT_MIN_CONFIDENCE, "min_windows": correlation.DEFAULT_MIN_WINDOWS,
                "max_gap": correlation.DEFAULT_MAX_GAP}
    shipped = {name: evaluate_day(day, preprocessing, **defaults) for name, day in days.items()}

    print("\nSweep over all seven days: confidence  min-windows  gap | false campaigns on the benign day | false coverage | quiet attack windows recovered")
    for row in rows:
        print(f"  {row['min_confidence']:<10} {row['min_windows']:<11} {row['max_gap']:<4}| {row['false_campaigns_on_benign_day']:<5} | "
              f"{row['false_coverage']:.3%} | {row['quiet_attack_windows_recovered']}/{row['quiet_attack_windows']} ({(row['recovery_rate'] or 0):.1%})")
    keys = ("min_confidence", "min_windows", "max_gap")
    print(f"\nBest setting with zero false campaigns and false coverage <= 0.5%: {None if chosen is None else {k: chosen[k] for k in keys}}")
    print(f"\nShipped defaults {defaults}:")
    for name, result in shipped.items():
        print(f"  {DAYS[name]:<26} {result['campaigns']:>4} campaigns | attack windows alerting alone {result['attack_windows_alerted_alone']:>6} | "
              f"quiet attack windows {result['quiet_attack_windows']:>6}, recovered {result['quiet_attack_windows_recovered']:>6} | "
              f"benign windows inside campaigns {result['benign_windows_in_campaigns']}")
        for category, counts in result["quiet_by_category"].items():
            print(f"      {category:<18} quiet {counts['quiet_attack_windows']:>6}  recovered {counts['recovered']:>6}")

    report = {"days": DAYS, "shipped_defaults": defaults, "shipped_results": shipped,
              "best_setting": None if chosen is None else {k: v for k, v in chosen.items() if k != "per_day"},
              "sweep": [{k: v for k, v in r.items() if k != "per_day"} for r in rows]}
    (reports_dir / "correlation_eval.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote {reports_dir / 'correlation_eval.json'}")


if __name__ == "__main__":
    main()
