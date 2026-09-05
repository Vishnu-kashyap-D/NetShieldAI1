# NetShield AI — Backend

FastAPI service wrapping the `cyber_ai` detection pipeline: ingest traffic CSVs, score
them through the trained Autoencoder + BiLSTM + hybrid risk fusion, store alerts in
MySQL, and expose them (plus stats, feedback, and retraining) to the dashboard.

## 1. Install dependencies

```bash
pip install -r backend/requirements.txt
```

(`cyber_ai`'s own dependencies — tensorflow, shap, scikit-learn, etc. — must already be
installed per the repo root `requirements.txt`; the backend imports `cyber_ai` directly,
it doesn't duplicate those.)

## 2. Configure the database connection

Copy `backend/.env.example` to `backend/.env` and fill in your MySQL credentials:

```bash
cp backend/.env.example backend/.env
```

```
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=netshield
```

## 3. Create the database once

```bash
cd backend
python scripts/create_database.py
```

This only creates the empty `netshield` database. Tables are created automatically the
first time the API starts (`Base.metadata.create_all` in `app/main.py`'s lifespan).

## 4. Make sure the model is trained

The API loads `artifacts/preprocessing.joblib`, `artifacts/models/autoencoder.keras`,
and `artifacts/models/bilstm_classifier.keras` at startup (see repo root README for
`python -m cyber_ai.train`). If they're missing or incompatible, the API still starts,
but `/api/health` reports `degraded` and ingest endpoints return errors until it's fixed.

## 5. Run it

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

Interactive API docs: http://localhost:8000/docs

On first startup against an empty `users` table, four demo accounts are seeded automatically
(see [Authentication](#authentication) below) so there's something to log in with immediately.

## Authentication

Every route except `GET /api/health` requires a valid session. A session is an opaque token
(`app/auth.py::create_session`) stored in the `sessions` table and set as an httpOnly cookie —
not a JWT, so logging out is a real row delete rather than waiting out a token's expiry.

Four roles exist (`app/auth.py::Role`), assigned to an account at creation and never
self-selected at login:

| Role | Can do |
|---|---|
| Viewer | Read alerts/stats/analytics, use both chatbots |
| Security Analyst | Viewer + submit feedback (`POST /api/feedback`) |
| Threat Hunter | Security Analyst + ingest traffic (`POST /api/ingest/*`) |
| Administrator | Threat Hunter + trigger retraining (`POST /api/retrain`) + manage users (`POST/GET /api/auth/users`) |

**Seeded demo accounts** (created once, only if the `users` table is completely empty —
`app/seed.py`), all sharing the password `NetShield@123`:

| Email | Role |
|---|---|
| `admin@netshield.ai` | Administrator |
| `analyst@netshield.ai` | Security Analyst |
| `hunter@netshield.ai` | Threat Hunter |
| `viewer@netshield.ai` | Viewer |

There's no public self-registration endpoint — an Administrator creates further accounts via
`POST /api/auth/users`. The frontend's mock/demo data mode (see `frontend/dashboard-app/`) does
**not** use any of this — it's a cosmetic, client-side-only session for presenting the UI without
a backend; only "Live API" mode talks to real auth.

## API surface

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/health` | None | Model-loaded status |
| `POST /api/auth/login` | None (this *is* login) | Verify email/password, set the session cookie |
| `POST /api/auth/logout` | Any role | Invalidate this browser's session |
| `GET /api/auth/me` | Any role | Current user's identity — used on page load to check for an existing valid session |
| `GET /api/auth/roles` | Any role | The fixed list of assignable roles |
| `POST /api/auth/users` | Administrator | Create an account |
| `GET /api/auth/users` | Administrator | List all accounts |
| `POST /api/ingest/csv` | Threat Hunter, Administrator | Upload a traffic CSV, score it, store alerts |
| `POST /api/ingest/demo` | Threat Hunter, Administrator | Score the repo's curated `demo/panel_demo_traffic.csv` (no upload needed — handy for testing/demos) |
| `GET /api/alerts` | Any role | List alerts, filterable by `risk_level`, `category`, `source_file`, `batch_id`, paginated |
| `GET /api/alerts/{id}` | Any role | Full alert detail incl. raw feature vector and SHAP explanations |
| `POST /api/alerts/{id}/chat` | Any role | Per-alert explainability chatbot, grounded in that alert's own data |
| `POST /api/chat` | Any role | General project/network-threat chatbot (not tied to an alert) |
| `GET /api/stats/summary` | Any role | Counts by risk level / category, for dashboard tiles |
| `GET /api/stats/timeseries` | Any role | Per-minute alert counts for the last N minutes, for a chart |
| `POST /api/feedback` | Security Analyst, Threat Hunter, Administrator | Analyst submits a validated label for an alert; appends to `data/feedback/validated_traffic.csv` (same file `cyber_ai.train --feedback-csv` reads) |
| `GET /api/feedback` | Any role | List submitted feedback |
| `POST /api/retrain` | Administrator | Kick off `cyber_ai.train` with accumulated feedback, in the background |
| `GET /api/retrain` / `GET /api/retrain/{id}` | Any role | Check retraining run status/metrics |

## Chatbots

Both `POST /api/alerts/{id}/chat` and `POST /api/chat` run on one Gemini key/model
(`GEMINI_API_KEY`/`GEMINI_MODEL` in `.env`) — see `app/chat_service.py`. The per-alert assistant
tries a deterministic matcher first (confidence, anomaly score, top SHAP features, glossary
lookups — works without any key at all) and only calls the LLM for genuinely open-ended
questions; the general assistant is LLM-only, grounded in a fixed, hand-verified project fact
sheet, and refuses anything outside "this project" or "network security threats." Both degrade
to an honest "unavailable" message rather than crashing if `GEMINI_API_KEY` is unset.

## Stream simulator

There's no live traffic feed yet, so `backend/scripts/stream_simulator.py` stands in for
one: it replays a CSV in small paced chunks against `POST /api/ingest/csv` instead of
scoring it all in one instant, so `/api/stats/timeseries` shows an actual trend and the
dashboard sees alerts arrive over time rather than all at once. Since `POST /api/ingest/*`
now requires a Threat Hunter or Administrator session, the script logs in first (defaults to
the seeded `hunter@netshield.ai`; override with `--email`/`--password` for a different account).

```bash
# make sure the server from step 5 above is already running, then in another terminal:
python backend/scripts/stream_simulator.py
```

Defaults to replaying `demo/panel_demo_traffic.csv` once, 15 rows every 2 seconds.
Useful flags:

```bash
# loop forever, replaying the file each time it runs out
python backend/scripts/stream_simulator.py --loop

# replay a real (large) CICIDS2017 file instead of the curated demo CSV
python backend/scripts/stream_simulator.py --input-csv MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --chunk-rows 50 --interval 1

# only store Medium/High alerts (matches predict.py's own CLI default), not every window
python backend/scripts/stream_simulator.py --alerts-only
```

When watching `/api/stats/timeseries` during a simulator run, pass a small
`bucket_seconds` (its default `minutes`-scale bucketing collapses a whole fast demo run
into one point) -- e.g. `GET /api/stats/timeseries?bucket_seconds=3`.

Known limitation: each chunk is windowed independently (no state carried between
requests), so a 10-row detection window that straddles a chunk boundary is never scored.
Acceptable for a demo/dashboard feed; a real production stream would need a stateful
sliding buffer server-side instead.

## Notes

- `POST /api/ingest/*` defaults to storing only Medium/High-risk windows (pass
  `include_all_windows=true` to store everything, which `/ingest/demo` does by default
  so the full demo narrative — including the quiet BENIGN stretches — is visible).
- `POST /api/retrain` runs `cyber_ai.train` as a background subprocess (it can take
  several minutes); poll `GET /api/retrain/{id}` for status. On success it automatically
  reloads the in-process model so the very next `/api/ingest/*` call uses the retrained
  weights — no server restart needed.
- Every route below `/api/health` requires a session -- see [Authentication](#authentication).
