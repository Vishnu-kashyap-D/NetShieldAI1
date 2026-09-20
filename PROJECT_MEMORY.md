# NetShield AI — Project Memory / Context-Recovery File

**Purpose of this file:** if a Claude Code session's context window overflows or resets,
hand this file back to Claude and it should be able to pick up where things left off.
It summarizes the whole project — what it is, what's built, what's pending, key
technical gotchas already solved, and how this user likes to work — as of the last
update below.

**Last updated:** 2026-09-13
**Repo root:** `E:\NetShield_AI\NetShieldAI1`
**GitHub remote:** `https://github.com/Vishnu-kashyap-D/NetShieldAI1` (public)
**User:** Sambhram Lingaraja (USN 1BY23AI138), BMS Institute of Technology and
Management, AI&ML dept, 7th Sem C Sec, course BAI701. Group members on shared
coursework: Sai Disha N, Sai Tarun Reddy S, Samartha S, Sambhram Lingaraja.
Teammate "Vishnu-kashyap-D" (GitHub) / a contributor "tanish" built the frontend.

---

## 1. What NetShield AI Is

An AI-driven network intrusion detection system (NIDS) — **not** an endpoint/antivirus
agent. It watches network *flow* statistics (not raw packets) and classifies threats
into 6 categories, trained on CICIDS2017. Core pipeline (unchanged since early sessions):

```
Traffic → clean/impute/scale → 10-row sequence window (stride 5, never crossing a
capture-file boundary) → Autoencoder (trained on BENIGN-only windows) → anomaly gate
(error > threshold) → [if anomalous] BiLSTM classifier (trained on attack-only windows,
6 categories) → Hybrid Risk Fusion (risk = max(normalized anomaly score, classifier
confidence)) → Low/Medium/High → [Medium/High] SHAP (GradientExplainer) → alert →
analyst feedback → retrain
```

6 attack categories: DoS/DDoS, Port Scanning, Brute Force, Botnet Activity, Malware
Traffic, Data Exfiltration (36 raw samples only — always flagged unreliable).

Sequential-gate design is a deliberate trade-off: BiLSTM/SHAP never run on traffic the
Autoencoder already dismissed, but this caps overall recall at ~54% — documented
everywhere as a known limitation, not a bug.

---

## 2. Repository Layout (what exists, what each part is)

```
cyber_ai/                  ML pipeline (data.py, windowing.py, modeling.py, train.py,
                            calibrate.py, hybrid_risk.py, explain.py, predict.py,
                            feedback.py, report_assets.py, latency_benchmark.py,
                            feature_selection.py, reporting.py, config.py)
configs/default.yaml       window_size=10, stride=5, 70/15/15 split, seed=42,
                            50k rows/class cap, 12 epochs each model
MachineLearningCVE/        CICIDS2017 raw CSVs (gitignored, 844 MB, present locally)
artifacts/                 trained models + preprocessing.joblib (gitignored, present)
demo/panel_demo_traffic.csv  curated 185-row live-demo CSV (committed)
reports/                   training_metrics.json, figures/, latency_benchmark.json (gitignored)
docs/                      pipeline_flowchart.svg/png, full_architecture.png, and every
                            report/PPT/PDF deliverable listed in section 6 below
backend/                   FastAPI service (see section 3)
frontend/dashboard-app/    React+TS+Vite SPA, 8 pages (see section 4)
frontend/netshield-dashboard.html   earlier single-file prototype, superseded
scripts/build_demo_csv.py  regenerates the demo CSV
vk.txt                     unrelated GitHub-contribution-streak filler file, ignore it
```

`git log` contains many `graph-greener!` commits touching `vk.txt` — these are
contribution-streak noise, not real project history. Filter them out when reading log.

---

## 3. Backend (`backend/`) — Current State

FastAPI + MySQL, wraps `cyber_ai` directly (imports it, doesn't shell out). Originally
built by Claude (this assistant) in an earlier session with just health/ingest/alerts/
stats/feedback/retrain — **since then, real authentication/RBAC and two Gemini chatbots
were added** (by the user's teammate + Claude, commit `b62b05b`). Current routers:
`health, auth, ingest, alerts, chat, stats, feedback, retrain`.

**Auth (`app/auth.py`, `app/models.py` User/UserSession, `app/seed.py`):**
- Real accounts, bcrypt-hashed passwords, opaque session tokens in a `sessions` table
  set as an httpOnly cookie (not JWT — logout is a real DB delete).
- 4 roles: Viewer < Security Analyst (+feedback) < Threat Hunter (+ingest) <
  Administrator (+retrain, +user management).
- 4 demo accounts auto-seed on first run against an empty `users` table, all password
  `NetShield@123`: `admin@netshield.ai`, `analyst@netshield.ai`, `hunter@netshield.ai`,
  `viewer@netshield.ai`. (This password is already public in `backend/README.md` —
  fine to reference. The real MySQL DB password is NOT in this file — see `backend/.env`,
  gitignored, ask the user directly if it's needed again.)

**Chatbots (`app/chat_service.py`, `app/feature_glossary.py`):**
- Both run on one Gemini key/model (`GEMINI_API_KEY`/`GEMINI_MODEL` in `.env` — **unset
  as of last check**, so both degrade to deterministic-only / "unavailable" gracefully).
- Per-alert assistant (`POST /api/alerts/{id}/chat`): deterministic matcher first
  (confidence, anomaly score, SHAP features, glossary), LLM fallback for open-ended Qs.
- General assistant (`POST /api/chat`): LLM-only, grounded in a fixed fact sheet, refuses
  off-topic questions.

**Known real bugs found & fixed this project (worth remembering, could resurface):**
- MySQL password containing `@` broke the raw SQLAlchemy connection string — fixed via
  `quote_plus()` in `app/config.py`.
- `uvicorn` script not on PATH after pip install — always use `python -m uvicorn`.
- `/api/stats/timeseries` defaulted to minute-wide buckets, which collapsed a fast
  stream-simulator run into one point — fixed with a `bucket_seconds` query param.
- (Fixed since) Retrain hot-swap used to have no quality gate; now `retrain.py` rejects a
  model whose BiLSTM accuracy / Autoencoder balanced accuracy regresses by >0.01 and restores
  the previous artifacts. Model reload is also shared across `uvicorn` workers (marker file).
- scikit-learn version is load-bearing: the committed `artifacts/preprocessing.joblib` was
  pickled under **1.7.2**; 1.8.0 fails every ingest with `'SimpleImputer' object has no
  attribute '_fill_dtype'`. Both requirements files are now exact-pinned (and `tf-keras` added).
- Keras-2-vs-Keras-3 incompatibility broke loading models trained on a different
  machine — root cause, not yet re-hit: `TF_USE_LEGACY_KERAS=1` is now set in
  `app/config.py` before any TensorFlow import, specifically to prevent this recurring.

**Stream simulator** (`backend/scripts/stream_simulator.py`): replays a CSV in small
paced chunks against `/api/ingest/csv` (now logs in as `hunter@netshield.ai` first,
since ingest requires Threat Hunter+). Confirmed working, reproduces the demo CSV's
scripted narrative (calm → DDoS → calm → Port Scan (2/6, genuinely mixed) → calm →
Botnet → calm) live.

**Live capture** (`backend/scripts/live_capture_feed.py`, new): converts a **real**
captured `.pcap` (from an isolated VirtualBox lab VM) into the model's 76-feature
schema using the pure-Python `cicflowmeter` package (Java CICFlowMeter unavailable
offline), with 4 documented workarounds for real bugs in that library (a flush bug, a
scapy/numpy Decimal incompatibility, a Decimal/float mixing bug, and a silent TCP-flag
miscounting bug where `packet.flags` resolved to the IP layer not TCP). This is how the
pipeline has been validated against genuinely captured traffic, not just CICIDS2017 replay.

---

## 4. Frontend (`frontend/dashboard-app/`) — Current State

React 19 + TypeScript + Vite, **no chart/UI library** (custom-built), built by the
user's teammate on a `tanish-frontend` branch, merged via PR #1. 8 pages: Dashboard,
Alerts, AlertDetail, Analytics, Feedback, Retraining, a "Shap" chatbot page, Login.
Has both a Mock/Demo mode (cosmetic, no backend) and Live API mode (real auth).
This assistant has **not** deeply audited the frontend internals (accessibility,
mobile responsiveness, etc. — flagged as open items, not yet checked).

---

## 5. Environment / How to Run (this machine specifically)

- Windows 11, Git Bash + PowerShell both available. Python at
  `...WindowsApps\PythonSoftwareFoundation.Python.3.12...`.
- **MySQL 8.0** installed and running as Windows service `MySQL80`. DB `netshield`,
  user `netshield` (password known to the user, stored in gitignored `backend/.env` —
  don't ask the user to repeat it in chat if avoidable, just have them check the file).
- No LibreOffice, no Poppler (`pdftoppm`), no Docker on this machine as of last check.
  Playwright + Chromium (headless) **is** installed now (used for real hands-on tool
  screenshots — see section 6) — a reliable way to get real, saved screenshots when the
  in-session Browser pane tool can't persist images to disk.
- To run the backend: `cd backend && python -m uvicorn app.main:app --reload --port 8000`
  (needs `pip install -r backend/requirements.txt` — includes bcrypt, google-genai,
  email-validator now, beyond the original fastapi/sqlalchemy/pymysql set).
- To run the stream simulator: `python backend/scripts/stream_simulator.py` (needs the
  backend already running).
- MLflow/Evidently/pytest/playwright were pip-installed on this machine during the MLOps
  report exercise (section 6) — available if needed again.

---

## 6. Deliverables Already Produced (all in `docs/` unless noted)

| File | What it is |
|---|---|
| `NetShieldAI_Project_Report.docx` | Full academic project report (13 sections), built before backend/auth/frontend existed — real figures/numbers from the retrained model at that time |
| `NetShieldAI_Viva_Presentation.pptx` | 22-slide viva deck, dark SOC-dashboard theme |
| `NetShieldAI_Study_QA.pptx` | 21-slide deep-dive Q&A study guide (12 questions: dataset, preprocessing math, architecture, models, metrics, roles of AE/BiLSTM/SHAP, feedback loop, windowing, backend, output, stream simulator, storage) |
| `NetShieldAI_DeepDive_Report.docx` | The long-form prose version of the same 12 questions, textbook-chapter style with real worked numeric traces (an actual DDoS window and a BENIGN window run through the real model, real numbers) |
| `NetShieldAI_Frontend_API_Brief.docx` | Short API brief + copy-paste AI prompt, written for the teammate building the frontend |
| `NetShieldAI_Improvement_Roadmap.pdf` | 7-page gap analysis: 6 phases (quick wins → portability → security hardening → scale/observability → model/data research → polish), ~90 checklist items, some marked "(verified)" where directly confirmed in code |
| `Final Report.docx` | A separate, much larger (13.8 MB) report — **not built by this assistant**, likely assembled by the user/teammate with many embedded screenshots; exists alongside the above |
| `full_architecture.png` | Diagram layering the application stack (auth, dashboard, chatbots) on top of the original 11-step ML pipeline diagram |
| Two earlier handover docs at `E:\bmsit\NetShieldAI_Handover_Summary.docx` (2026-08-22) and `docs/NetShieldAI_Handover_Summary_2026-08-26.docx` | Session-to-session handover snapshots, same spirit as this file but narrower in scope |

**Separately, for a BAI701 (MLOps) course assignment (unrelated to the NetShield AI
product itself, but done using this project as the practice ground):**
`E:\bmsit\MLOPS\CCA1_MLOps_Tools_Report_Group2.docx` — a filled-in CCA1 report using the
group's real BMSIT template, covering Git/GitHub, MLflow, VS Code, GitHub Actions,
FastAPI, Evidently AI, MLflow Model Registry — with real hands-on screenshots (a real
MLflow run + registered model, a real Evidently drift report, the real GitHub repo, the
real live FastAPI docs, a real local pytest dry-run of a CI workflow that was
deliberately **not** pushed to the live repo per the user's explicit instruction).

---

## 7. Open Items / Roadmap (see the Improvement Roadmap PDF for the full ~90-item list)

**Fix Plan v2 status (`E:\bmsit\NetShield_Fix_Plan_v2.pdf`), as of 2026-09-20:**
- Phase 4 (DB/infra polish) — done and committed locally (`fec13b6 phase 4 done`): unique
  `Feedback.alert_id` + upsert, `.env.example` documented, exact pins, cross-worker model
  reload, `feature_schema_version` on alerts, startup migration (`app/migrations.py`).
- Phase 5 (testing & process) — done, **uncommitted** when written: `backend/tests/` (~200
  tests; see `backend/README.md` "Tests"), plus `docs/OPERATIONAL_RUNBOOK.md`,
  `docs/THREAT_MODEL.md`, `docs/LAB_RULES_OF_ENGAGEMENT.md` (R5-R10 there are *proposed*
  wording for the user to confirm — only R1-R4 record existing practice).
- Phase 6 (research stretch) — done on 2026-09-20 EXCEPT 6.2 (UNSW-NB15, dataset unavailable; user said skip).
  Uncommitted when written. Results + caveats: `docs/PHASE6_FINDINGS.md`. What exists:
  * 6.7 `ThreatLabel` flags Data Exfiltration "unreliable" everywhere (`frontend/.../constants/reliability.ts`).
  * 6.3 `python -m cyber_ai.calibration_check`: confidence >=0.99 is right 100% (10,561 windows); <0.8 right ~1/3.
    High risk = 97.6% real attacks, Medium 53%, Low 45.5% (Low is NOT safe).
  * 6.1 "Unknown" abstention (`UNKNOWN_CONFIDENCE_THRESHOLD`, `--unknown-threshold`): OFF by default because at the
    recommended 0.9 the demo's 3 Botnet windows (conf 0.70-0.78) become Unknown. Analyst can't validate "Unknown".
  * 6.4 `cyber_ai/adversarial_robustness.py`: adaptive slow/pad/jitter attacker hides only 3.2% of detected windows
    (gate detection 53.7% -> 52.0%); bigger issue is 46% of attacks (93% of Port Scan) are never flagged anyway.
  * 6.5 drift: `cyber_ai/drift.py`, `score_batches` table, `GET /api/stats/drift`, Analytics "Model drift" card;
    reference `artifacts/drift_reference.json` (written by train.py; `python -m cyber_ai.drift` rebuilds it).
  * 6.6 cross-window "campaigns": FIRST DESIGN (CUSUM on risk) FAILED evaluation (215 false campaigns on benign Monday)
    and was replaced by a persistence detector (>=8 consecutive windows, same category, >=99% classifier confidence;
    classifier is run on ALL windows). Recovers 97.9% of the Port Scanning windows the gate misses, 0 false campaigns
    on benign day; does NOTHING for Brute Force/Botnet/Web. `campaigns` table, `GET /api/campaigns`, Dashboard card.
  * Shared helper `cyber_ai/holdout.py` rebuilds the exact held-out split (verified against training_metrics.json);
    scores cached in `reports/.cache/` (gitignored). Big caveat: stride-5/size-10 windows + random split overlap
    train/test, so all accuracy/calibration numbers are optimistic (documented in README + findings).
- Four small threat-model items FIXED on 2026-09-20 (tests in `backend/tests/test_hardening_fixes.py`):
  feedback `analyst` now comes from the session; `ingest_csv` is a plain `def` (worker thread, no event-loop
  blocking); `/api/health` no longer returns the artifacts path/exception (logged instead; `artifacts_dir` field
  removed); unknown-email login checks a bcrypt decoy so it takes as long as a wrong password.
  Still open: no password-change/delete-account endpoint (seeded demo accounts share a public password).

Top priority (Phase 1 of the roadmap):
1. Retrain quality gate (don't hot-swap the live model if new metrics are worse)
2. Login rate-limiting / account lockout
3. A first pytest suite for the backend
4. Set `GEMINI_API_KEY` so chatbots run at full capability

Other named gaps: no Docker, no CI/CD pipeline (plain GitHub ≠ CI/CD — this was
explicitly clarified with the user), no cross-dataset (UNSW-NB15) validation, no
concept-drift monitoring in production, frontend accessibility/mobile unaudited,
no DB migrations tool, multi-worker model-reload mismatch, and more — full detail in
`docs/NetShieldAI_Improvement_Roadmap.pdf`.

---

## 8. How This User Likes To Work (behavioral notes for future sessions)

- Wants **deep, elaborated explanations** when asking to understand something — not
  compressed bullet paragraphs. Explicitly said prior answers were "too short" and
  asked for "deep analysis report type" content, because teammates who don't understand
  the project need to be taught, not given a cheat-sheet. Worked examples with real
  numbers (not toy/abstract ones) land well.
- Frequently asks for deliverables as actual files (docx/pptx/pdf) rather than just
  chat text — and expects them **verified** before delivery (structural validation,
  content extraction, not just "it built without error"). Catches and appreciates when
  I proactively find and fix a real bug in a deliverable before sending it (e.g. a
  broken Unicode glyph in a PDF, a wrong chart option that would've hidden data).
- **Very protective of the live GitHub repo** — has explicitly said multiple times not
  to commit, push, or change anything on it without being asked. Read-only viewing
  (browsing commits, cloning info) is fine; any write action needs explicit sign-off
  first, even something as small as adding a CI workflow file.
- Comfortable with me installing tools and doing real hands-on execution (MLflow,
  Evidently, Playwright, pytest) rather than describing things abstractly — prefers
  genuine practice over simulated/mocked evidence wherever feasible, but is
  understanding when a tool (like Docker) isn't installed and offers reasonable
  alternatives when asked.
- Is a student building this as a capstone/coursework project (BMSIT, BAI701 MLOps
  course) — asks both product-engineering questions (deployment topology, real traffic
  testing) and academic-assignment questions (fill in this exact template) in the same
  conversation. Keep both hats in mind.
- Uses a password manager / knows secrets already exist — never needed me to fabricate
  or guess credentials; asks direct, practical questions about portability (e.g. "would
  this run on my friend's laptop") rather than assuming things.

---

## 9. If Context Was Just Reset — Suggested First Questions To Ask The User

1. "What have you been working on since [last updated date above]?" — a lot may have
   changed given how active this project is (frontend/auth/chatbots all appeared
   between two sessions previously).
2. Check `git log --oneline --invert-grep --grep="graph-greener" --grep="Update vk.txt"`
   for real commits since this file's last-updated date.
3. Check whether `backend/.env` has `GEMINI_API_KEY` set yet, and whether MySQL80 is
   running, before assuming backend state.
4. Ask whether this file itself should be updated/regenerated once caught up.
