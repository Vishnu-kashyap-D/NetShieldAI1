# NetShield AI — Operational Runbook

**For:** Security Analysts (and Threat Hunters / Administrators acting as one)
**Question this answers:** *A High-risk alert just appeared. What do I actually do?*

Everything below is something the dashboard really offers; nothing here assumes a feature that doesn't exist. Where NetShield **cannot** help you, that is stated plainly (see "What NetShield does not tell you").

---

## 0. What a High alert means

Each alert is one **10-row window** of network-flow records. Two models looked at it:

1. The **Autoencoder** scored how unlike normal traffic the window is (its *anomaly score*, compared with a threshold learned from data).
2. Only if that gate fired, the **BiLSTM classifier** named the most likely attack category and gave a *confidence*.

The **risk score** fuses the two, and the level is a band of that score:

| Level | Meaning | What to do |
|---|---|---|
| **High** | At least as suspicious as a typical confirmed attack window in the validation data | Work it now — steps 1–5 below |
| **Medium** | Above what normal traffic usually scores, below a typical attack | Review when High alerts are clear; look for repeats |
| **Low** | Scores like known-normal traffic (stored only if ingest was run with "all windows") | No action |

The category on the alert (DoS / DDoS, Port Scanning, Brute Force, Botnet Activity, Malware Traffic, Data Exfiltration) is the **model's best guess**, not a verdict.

---

## 1. Triage — the five steps

### Step 1 · Open the alert
*Alerts* page → filter **Risk level = High** → open the alert. Note the **source file**, the **window start/end row numbers**, the **predicted category** and **confidence**, and the **anomaly score vs. its threshold**. You need the source file and row range in Step 5.

### Step 2 · Check the SHAP evidence
The alert page shows two ranked cards: what drove the **classifier's** call and what drove the **anomaly score**.

- Hover the ⓘ next to a feature name for a plain-language definition.
- Ask: *do the top features make sense for the predicted category?* Rules of thumb: a DoS / DDoS call is usually driven by packet/byte rates and flow durations; a Port Scanning call by very short flows and small packet counts. Evidence that points somewhere else deserves suspicion.
- **Read the caveat under the chart**: SHAP shows what moved the *model's output*, not proof that a feature *caused* the attack.
- If the card says **"Explanation unavailable"**, the alert was ingested without SHAP (or was beyond the first 20 classified windows of that upload). It is not an error; use Step 3 and the raw features instead.

### Step 3 · Confirm with the assistant
Use **"Ask about this prediction"** on the same page. Good first questions (they are one-click chips): *Why was this classified this way? · Which features contributed most? · Why is the risk high? · How confident was the model?*

- It answers **only from this alert's own stored data** — it cannot make a new prediction and won't invent numbers.
- Numeric questions (confidence, anomaly score, risk, top features, feature definitions) work even if the language-model service is down. Open-ended questions then return an honest "unavailable".
- It is rate-limited (20 messages/minute per user, shared with the sidebar chatbot).

### Step 4 · Record your verdict (Security Analyst and above)
In **Analyst feedback**:

- **"Yes, confirm prediction"** if the category is right, or
- **"No, correct it"** and pick the true category (or **Normal** for a false alarm), and add a note explaining why.

Things to know:

- **One verdict per alert.** Submitting again *updates* it (the retraining data is corrected, not duplicated).
- A **Viewer** cannot submit; the form says so.
- Feedback is **training data for the next retrain**, not an instant change: it does not alter this alert or the live model.
- If you get a **409** about the feature set, the alert was scored under an older feature set than the deployed model. Re-ingest the traffic and give feedback on the fresh alert.
- **Only submit a label you are sure of.** A wrong label is retrained on. When unsure, add a note and escalate instead of guessing.

### Step 5 · Escalate or hand off
NetShield **detects and explains**; it does not block, quarantine or open tickets. Acting on a real incident happens outside it. Escalate to the **Administrator / Threat Hunter** (and follow your organisation's incident process) when any of these is true:

| Trigger | Why |
|---|---|
| Several High alerts from the **same source file** within a short span | A sustained event, not a one-off window |
| High alert whose SHAP evidence **fits** the category and the assistant agrees | Likely real |
| Predicted **Data Exfiltration** | The whole dataset has only ~36 rows of it (one window in the held-out test set), so the model's call on it is **statistically unreliable** — verify by hand |
| High risk but the **category looks wrong** for the evidence | The alarm may be real while the label is not (e.g. tooling like hping3 or hydra has been seen labelled *Malware Traffic*) — trust the anomaly, not the label |
| You cannot decide | A second pair of eyes beats a wrong training label |

To find *who* is involved, go back to the original capture / flow log using the **source file + window row range** from Step 1.

---

## 2. What NetShield does not tell you

- **No IP addresses or hostnames.** The model's 76 features are flow statistics (the port column is deliberately excluded). An alert says *this stretch of traffic looks like a DoS*, not *which host*. Correlate with the source capture.
- **A quiet dashboard is not a clean bill of health.** The Autoencoder gate currently misses roughly **44 %** of attack windows in held-out evaluation (hybrid false-negative rate); those windows are never classified or alerted on. About **9 %** of normal windows raise a false alarm. Current figures are on the *Analytics* page (model card) — check them, they change after a retrain.
- **Confidence is not accuracy.** A model can be very confident and wrong on traffic unlike its training data (CICIDS2017).
- **Windows straddling a chunk boundary are never scored** when traffic arrives via the stream simulator.

---

## 3. Administrator tasks

### Retraining (Administrator only)
Run it when a meaningful batch of *reliable* feedback has accumulated — not after every alert. *Retraining* page → **Start a retraining run** → confirm. It runs in the background for several minutes; only one run can be active (a second attempt returns **409**).

The run ends in one of three states:

| Status | Meaning | Live model |
|---|---|---|
| **completed** | Trained, and headline metrics were **not worse** than the deployed model's | Replaced — all server workers pick it up on their next request |
| **rejected** | Trained fine but **regressed** (BiLSTM accuracy or Autoencoder balanced accuracy dropped >0.01) | **Unchanged** — the previous files are restored; the reason is shown on the run |
| **failed** | The trainer crashed or produced no metrics | **Unchanged** |

A *rejected* run is the safety net working, not a fault — usually the feedback batch was small or skewed. Review the feedback log for wrong labels before trying again.

### Accounts
Only Administrators create accounts (there is no self-registration). Give the **least** role needed: Viewer (read), Security Analyst (+ feedback), Threat Hunter (+ ingest traffic), Administrator (+ retrain, + users). The four seeded demo accounts share a password that is printed in the README — use them for demos only. There is no password-change or delete-account endpoint yet, so before real use create proper accounts and remove the demo rows directly in the database.

### If sign-in is refused with "too many failed attempts"
The lockout is 5 failures per address+account within 5 minutes and clears by itself (the message says how long). It is per server process and resets on restart.

---

## 4. Quick reference

| I want to… | Where | Minimum role |
|---|---|---|
| See alerts, stats, model metrics | Alerts / Dashboard / Analytics | Viewer |
| Ask the assistants | Alert page / sidebar | Viewer |
| Submit or correct a verdict | Alert page → Analyst feedback | Security Analyst |
| Score new traffic | Ingest (stream simulator / CSV upload) | Threat Hunter |
| Retrain the model | Retraining page | Administrator |
| Create accounts | `POST /api/auth/users` | Administrator |
