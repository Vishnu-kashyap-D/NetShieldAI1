# Phase 6 — Findings (model research on the deployed detector)

What was measured about the deployed NetShield model, what it showed, and how far each result can be trusted.
Every number here is reproducible with a script in `cyber_ai/` (commands at the end) and every script is
**analysis-only**: it reads `artifacts/` and the CICIDS2017 CSVs and writes into `reports/`.

**Skipped:** 6.2 (cross-dataset validation on UNSW-NB15) — the dataset is not available. Nothing below says
anything about traffic from another network or another dataset.

---

## 0. Read this first — caveats that apply to everything below

1. **Optimistic split.** Windows are 10 rows with a stride of 5, so each shares half its rows with each
   neighbour, and the train/validation/test split is random at window level. For classes kept whole (most attack
   classes), roughly nine in ten test windows have a half-overlapping neighbour in training. Accuracy, calibration
   and detection figures are therefore *upper-end* estimates. A split by capture day would be a fairer test and is
   the single most valuable follow-up.
2. **One dataset.** CICIDS2017 is a synthetic testbed; real networks differ.
3. **Faithful reconstruction.** `cyber_ai/holdout.py` rebuilds the exact validation/test windows the trainer used
   (20,282 / 20,283 windows) and *refuses to run* if they do not match `reports/training_metrics.json`, so no result
   is computed on the wrong windows.
4. **Where the numbers come from.** Tables are copied from `reports/*.json`, produced on 2026-09-20 against the
   committed `artifacts/`. Retraining changes them; re-run the scripts.

---

## 1. Calibration (6.3) — is "99.99% confident" true?

*Script:* `python -m cyber_ai.calibration_check` → `reports/calibration.json`, `figures/calibration_reliability.png`.
*Data:* the 12,783 held-out attack windows (the same ones the trainer reported classifier accuracy on).

**Yes, at the top end; no in the middle.**

| Stated confidence | Windows | Actually right |
|---|---:|---:|
| ≥ 0.99 | 10,561 | **100.0 %** (95 % CI 99.95–100) |
| 0.9 – 0.99 | 1,298 | 98.9 % |
| 0.8 – 0.9 | 231 | 93.5 % |
| 0.7 – 0.8 | 138 | 55.8 % |
| 0.6 – 0.7 | 189 | 26.5 % |
| below 0.6 | ~366 | 11 – 29 % |

- Overall: accuracy 96.07 %, mean confidence 96.89 %, ECE 0.021, Brier 0.053 — a *slightly* overconfident model
  whose overconfidence lives entirely in the low-confidence tail (a window it is 65 % sure of is right about a
  quarter of the time).
- Confidence is an excellent "should I trust this?" signal: when the classifier is right its mean confidence is
  0.985, when wrong 0.583, and confidence separates right from wrong with **AUROC 0.991**.
- **Temperature scaling does not help** (fitted T = 1.13 on validation): ECE 0.0207 → 0.0231, log-loss 0.1295 →
  0.1281. The model is already well calibrated where it matters; not worth adding.
- **Per predicted class** the picture is very uneven: DoS/DDoS 99.99 % precise, Port Scanning 99.9 %, Brute Force
  70.9 %, **Malware Traffic 21.1 %, Botnet Activity 12.4 %**, Data Exfiltration never predicted. Those low
  precisions are why a category on its own should not be quoted without its confidence.

**What each risk level means in practice** (fused score, held-out test windows):

| Level | Windows | Really attacks |
|---|---:|---:|
| High | 6,645 | **97.6 %** |
| Medium | 1,179 | 53.3 % |
| Low | 12,459 | **45.5 %** |

High is trustworthy; Medium is a coin flip; and **Low is not "safe"** — 45 % of Low windows are attacks the model
missed (the sequential gate's known recall ceiling). These figures are now in the operational runbook.

---

## 2. "Unknown" instead of a forced category (6.1)

*Script:* `python -m cyber_ai.abstention_analysis` → `reports/abstention_analysis.json`, `figures/abstention_tradeoff.png`.
*Feature:* `UNKNOWN_CONFIDENCE_THRESHOLD` (backend) / `--unknown-threshold` (CLI). **Off by default.**

**The problem.** The BiLSTM is trained on attack windows only, so it cannot answer "none of these". Whenever the
Autoencoder flags something that is not one of the six attacks — a false alarm on ordinary traffic, or (in the lab)
a tool like hping3 that resembles none of them — the classifier is forced to name one anyway.

**The evidence.** Among windows the Autoencoder flags, classifier confidence separates real attacks from false alarms
(benign windows) with **AUROC 0.98** on both validation and test. Median confidence: real attacks ≈ 1.00, false
alarms ≈ 0.60.

| Threshold | Real attacks still named | Accuracy of those names | False alarms → Unknown |
|---:|---:|---:|---:|
| 0.5 | 99.2 % | 99.31 % | 29.7 % |
| 0.7 | 98.3 % | 99.81 % | 66.4 % |
| 0.8 | 97.9 % | 99.93 % | 78.4 % |
| **0.9** | **97.5 %** | **99.97 %** | **88.4 %** |
| 0.95 | 97.0 % | 100.00 % | 94.5 % |

The threshold was chosen on the **validation** windows (the strictest that keeps ≥ 97 % of real attacks named and
those names ≥ 99.8 % accurate → **0.9**), then confirmed on test. Only the *label* changes: confidence, anomaly
score, risk score and alert counts are identical with the option on or off (tested).

**Why it is off.** On `demo/panel_demo_traffic.csv` the Botnet windows score 0.70 – 0.78 confidence, so turning it on
would relabel the demo's Botnet scene "Unknown". That is arguably the *honest* answer for those windows (this
classifier is only ~75 % right on Botnet), but it changes what a scripted demo shows, so it is left to a deliberate
choice. To enable: `UNKNOWN_CONFIDENCE_THRESHOLD=0.9` in `backend/.env`.

**Limits.** False alarms are a *proxy* for unfamiliar traffic. A held-out attack **class** would be the real test
(it needs a retrain without that class) and was not run; the lab's hping3/hydra traffic is the natural real-world
check. An analyst cannot validate an alert as "Unknown" (the API refuses it), and the dashboard, filters, chatbot and
feedback form all handle it.

---

## 3. Adversarial robustness (6.4)

*Script:* `python -m cyber_ai.adversarial_robustness` → `reports/adversarial_robustness.json`, `figures/adversarial_robustness.png`.

**Question.** Can real attack traffic be reshaped to slip under the Autoencoder's anomaly threshold?
**Method.** Take the held-out attack windows; apply changes an attacker can make to their own traffic without
stopping the attack — *slow it down* (×2 … ×200), *pad every packet* (+10 … +1000 bytes), *jitter the timing*
(0.5× … 5× the mean gap), and combinations — editing the flow **features** consistently (slowing a flow also divides
its packets/s; padding also raises the byte totals and byte rate); re-score with the frozen model. The unperturbed
windows are first pushed through the same code path and must reproduce the cached scores, or the run aborts.

**Findings.**

- **Crude shaping backfires.** Padding ≥ 500 B or the heavy combined setting pushes detection to 100 %: the
  Autoencoder learned "normal", so traffic that moves *away* from normal is flagged more, not less. Slowing raises
  detection from 53.7 % to 75 % (×200). Jitter is neutral.
- **A best-case adaptive attacker** (per window, the best of all 96 slow × pad × jitter combinations) hides only
  **222 of 6,867** detected windows (**3.2 %**); overall gate detection goes 53.7 % → **52.0 %**.
- **But it is very uneven by category:**

| Category | Attack windows | Gate already detects | Of those, hideable by shaping |
|---|---:|---:|---:|
| DoS / DDoS | 9,652 | 68.9 % | **0.5 %** — robust |
| Port Scanning | 2,725 | **6.7 %** | **97.8 %** of the few detected |
| Botnet Activity | 59 | 20.3 % | 41.7 % |
| Brute Force | 321 | 5.6 % | 27.8 % |
| Malware Traffic | 25 | 8.0 % | 2 of 2 |

- **The larger weakness is not evasion at all**: with *no* effort, 46 % of attack windows (93 % of Port Scanning)
  are never flagged. An attacker does not need to shape anything to be missed; §5 addresses exactly that.

**Limits.** Feature-space approximation, not re-captured packets — the lab (pcaps of shaped hping3/hydra runs) is the
follow-up that would confirm it. The study ignores whether the attack still *works* once slowed or padded (a slowed
flood is a weaker flood), so evasion rates are upper bounds. A **mimicry** attacker who moves toward the benign
distribution — the realistic strong adversary — was not modelled.

---

## 4. Drift monitoring (6.5)

*Code:* `cyber_ai/drift.py` (pure), `ScoreBatch` table, `GET /api/stats/drift`, dashboard **Model drift** card.

**Design.** The `alerts` table only keeps Medium/High windows, so it cannot show whether *ordinary* traffic has
changed. Each ingest therefore records a histogram of every window's anomaly score, binned by the deciles of benign
validation windows the Autoencoder did not flag (`artifacts/drift_reference.json`, written by every training run). The
endpoint pools recent ingests and computes the **Population Stability Index** against the reference: < 0.1 stable,
0.1 – 0.25 watch, > 0.25 drifting. Only the *quiet* end is compared, so a genuine burst of attacks is not mistaken for
drift; the alert rate is shown alongside for context.

**Validation on held-out data** (checked before building on it):

| Traffic | PSI | Verdict |
|---|---:|---|
| Held-out benign windows | 0.003 | stable ✔ |
| The same, scores shifted ×1.5 | 0.154 | watch ✔ |
| Attack-only windows | 0.596 | drifting ✔ |

**Robustness properties (all tested):** an ingest is counted once however often its file is re-sent (a deliberate
replay counts as new traffic); counts binned under a previous model are excluded after a retrain, never compared; too
few windows (< 200) is reported as "not enough data", never as "stable"; a failure recording the histogram can never
fail an ingest.

**Limits.** It detects a shift in how ordinary traffic *scores*, not a fall in accuracy (that needs labels). It has
been validated on held-out data and synthetic shifts, **not on a real drifting network**. It is not connected to any
alerting.

---

## 5. Cross-window correlation (6.6)

*Code:* `cyber_ai/correlation.py` (pure), `CorrelatedCampaign` table, `GET /api/campaigns`, dashboard **Sustained
activity** card. *Evidence:* `python -m cyber_ai.correlation_eval` → `reports/correlation_eval.json`.

**The gap.** Detection is per 10-row window and the design is sequential: the Autoencoder decides which windows the
classifier ever sees. A slow or simple attack that keeps every window unremarkable never crosses the alert bar. On
real, time-ordered traffic that is not hypothetical — the gate lets **93 % of Port Scanning windows** through (§3),
because a scan looks *simple* to an autoencoder trained on benign traffic.

**First design — rejected on its own evidence.** The obvious tool is a CUSUM (running total) over the window risk
score. It was built and evaluated on seven full capture days, and it failed: on **Monday, which is pure benign
traffic, it reported 215 false campaigns covering 18,463 benign windows (~18 % of the day)**, and no setting in a
20-point sweep produced a clean day. Bursty benign traffic accumulates risk just as a slow attack does. It was
discarded rather than shipped with a caveat.

**The signal that works.** Shown the very windows the gate missed, the classifier is *sure*: quiet Port Scanning
windows have classifier confidence **≈ 0.999** (10th percentile 0.998), while quiet benign windows are mostly under
0.93 and scattered across categories (the classifier was never trained on benign traffic, so on it the label jumps
around). So the layer looks for **persistence**: ≥ 8 consecutive windows the classifier reads as the *same* category
at ≥ 99 % confidence (one off-pattern window tolerated, ≥ 75 % of the run on-pattern), whether or not the anomaly
gate flagged any of them. It only ever adds information: no alert, label or risk level changes (tested).

**Results** — seven full CICIDS2017 capture days, in order, defaults `0.99 / 8 windows / gap 1`:

| Day | Contains | Campaigns | Quiet attack windows* | Recovered | Benign windows inside campaigns |
|---|---|---:|---:|---:|---:|
| Monday | benign only | **0** | 0 | — | **0** |
| Tuesday | FTP / SSH brute force | 0 | 1,619 | 0 | 0 |
| Wednesday | DoS variants | 320 | 7,254 | 2,206 (30 %) | 1,029 |
| Thursday | web attacks | 0 | 399 | 0 | 0 |
| Friday am | botnet | 0 | 346 | 0 | 0 |
| Friday pm | **port scan** | 136 | **17,060** | **16,695 (97.9 %)** | 382 |
| Friday pm | DDoS | 83 | 11,745 | 7,438 (63 %) | 22 |

\* attack windows that raised no per-window alert on their own.

- **Zero false campaigns** on the benign day, and on every day without a flood or scan. Its false coverage over all
  benign windows is 0.38 %; those are benign-*labelled* windows inside attack periods (CICIDS labels a window by its
  last row, so interleaved rows are mislabelled) — a conservative count, not proof they are false alarms.
- **Port Scanning is the win**: 16,695 of the 17,060 windows the gate never flagged are now covered.
- **It does nothing for Brute Force, Botnet or web attacks** (1,619 / 346 / 399 quiet windows, none recovered): the
  classifier's confidence on them is too low (median 0.88 / 0.61 / 0.74) to separate them from benign traffic without
  false alarms. Silence about those categories from this layer means nothing.
- On DoS/DDoS it mostly *summarises* — dozens of alerts become one campaign — and recovers 30 – 63 % of the windows
  that did not alert individually.

**Choosing the defaults.** `min_confidence` 0.99 is the knee: at 0.95 the benign day already produces false campaigns
(1 – 227 depending on run length), at 0.99 and above none. `min_windows` 8 is a deliberate margin — the sweep's own
rule would pick 5 (0.4 points more recovery, 69.0 % vs 68.6 %), but a run of 8 windows spans ~45 rows and is harder to
hit by chance.

**Limits.**
- The model was trained on windows drawn from these same files, so absolute recovery is optimistic; the *comparison*
  with per-window alerting uses the same scores and is fair.
- It runs per uploaded file. The stream simulator's tiny chunks (one window or none) can never form a campaign.
- It makes the classifier score **every** window instead of only the flagged ones. **Measured cost:** about
  **0.5 ms extra per window**, i.e. ingest takes roughly **1.4–1.5×** as long (real model, 60,000-row files, five
  alternating off/on runs, medians: benign day 12.2 s → 18.2 s, DDoS day 17.7 s → 24.8 s for ~12,000 windows). Per-window
  results are byte-identical either way. Wall-clock times on the test machine varied up to 3× between runs, so trust the
  ratio, not the seconds. (Scoring the extra pass in batches of 1024 instead of 256 was worth ~1.8× on its own.)
  `CAMPAIGN_DETECTION_ENABLED=false` turns it off.
- Not evaluated on real captured traffic from the VM lab.


---

## 6. Data Exfiltration reliability warning (6.7)

The whole dataset holds **36 rows** of `Infiltration` (the source of the Data Exfiltration category) — one window in
the held-out test set — so its precision and recall mean nothing (the classifier never once predicts it on held-out
data). Rather than synthetically over-sampling network flows (which invents traffic that never existed), the
dashboard now marks the category **unreliable** wherever it appears: an inline flag with an explanation in the alerts
list, recent alerts, alert detail (plus a banner), the feedback panel and the category chart. The list of flagged
categories is a single constant (`frontend/dashboard-app/src/constants/reliability.ts`) kept in step with
`data.low_sample_categories` in `training_metrics.json`.

---

## Reproducing everything

```powershell
python -m cyber_ai.calibration_check
python -m cyber_ai.abstention_analysis
python -m cyber_ai.adversarial_robustness
python -m cyber_ai.drift
python -m cyber_ai.correlation_eval      # ~15 minutes: scores seven full capture days
python -m pytest backend/tests           # 300+ tests, incl. the maths behind every analysis above
```

The first script run rebuilds the held-out split (~4 min) and caches it in `reports/.cache/` (git-ignored).
