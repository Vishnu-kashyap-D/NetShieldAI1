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

Both requirements files are **exact-pinned** (`==`) to a set verified working together, and one pin
is load-bearing: the committed `artifacts/preprocessing.joblib` was saved under scikit-learn
**1.7.2**, and 1.8.0 can't run it (every ingest fails with `'SimpleImputer' object has no attribute
'_fill_dtype'`). Also required, though easy to miss: `tf-keras`, which `TF_USE_LEGACY_KERAS=1`
needs in order to load the Keras-2-format models. To run the tests: `pip install -r
backend/requirements-dev.txt`, then `python -m pytest backend/tests`. To bump a pin: change it in the
requirements file, reinstall into a fresh venv, run `pip check`, run the tests, score the demo CSV
(`POST /api/ingest/demo`) — and retrain if the bump touches scikit-learn or TensorFlow, so the
artifacts are re-saved under the new version.

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

### Security hardening

What protects the API itself (all of it verified with real requests, not just read off the code):

| Protection | How it works | Where |
|---|---|---|
| **Hashed sessions** | The DB stores `sha256(token)`, never the token. The raw token exists only in the browser's cookie, so a leaked copy of the `sessions` table can't be replayed as logins. | `app/auth.py` |
| **Login lockout** | 5 failed attempts per (client IP, email) — and 20 per client IP across all emails — within 5 minutes → `429` + `Retry-After`. Only failures count; a blocked attempt records nothing; success clears the counter. | `app/routers/auth.py`, `app/ratelimit.py` |
| **CSRF: Origin verification** | Every `POST/PUT/PATCH/DELETE` carrying an `Origin` (or `Referer`) must come from a dashboard origin in `cors_origins` (or this server itself, for `/docs`) — otherwise `403`. `SameSite=Lax` alone isn't enough: "same site" ignores ports, so a page on any *other* local port could log you out (reproduced against this API before the fix). Requests with neither header (curl, the scripts in `backend/scripts/`) aren't browser cross-site requests and pass. | `app/security.py` |
| **Security headers** | `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` everywhere; on `/api/*` also a `default-src 'none'` CSP and `Cache-Control: no-store`; `Strict-Transport-Security` only when actually served over HTTPS. CSP is deliberately not applied to `/docs` (it loads assets from a CDN). | `app/security.py` |
| **Chat limits** | Question ≤ 2,000 chars, history ≤ 40 turns, one message ≤ 8,000 chars, and 20 chat requests/minute per user (shared by both chatbots — either may call a paid LLM). | `app/schemas.py`, `app/routers/chat.py` |
| **Untrusted CSV labels** | The uploaded CSV's `Label` column is pasted into the per-alert chatbot's LLM prompt, so a label outside CICIDS2017's known vocabulary is stored as `Unrecognized` instead of verbatim. | `app/detection_service.py` |
| **Bounded inputs** | Upload size cap (`MAX_UPLOAD_BYTES`), login password ≤ 128 chars, malformed CSV → clean `422`. | `app/routers/ingest.py`, `app/schemas.py` |

Limits worth knowing: the lockout and chat limits live in process memory, so they're **per worker** and reset on restart (a multi-worker deployment needs a shared store such as Redis — see [Running with multiple workers](#running-with-multiple-workers)). The client IP is the direct socket peer — `X-Forwarded-For` is deliberately *not* trusted, since any client can forge it — so behind a reverse proxy every request looks like it comes from the proxy until that's configured. Old sessions from before hashing was introduced are invalid: everyone signs in once more.

### Dependency auditing

```bash
# frontend
cd frontend/dashboard-app && npm audit

# backend + cyber_ai: run pip-audit from its OWN throwaway venv and point it at the environment the
# app actually runs in, so auditing can never change the packages you run on (the TensorFlow / Keras /
# NumPy combination in particular is fragile -- see cyber_ai/__init__.py)
python -m venv .audit-venv
.audit-venv/Scripts/pip install pip-audit          # Linux/macOS: .audit-venv/bin/pip
.audit-venv/Scripts/pip-audit --path <your-site-packages-directory>
```

A finding only matters if the vulnerable code path is reachable from this app. For example, every
Keras advisory is about loading an *untrusted* model file, and NetShield only ever loads the
artifacts it trained itself — so **never point `artifacts/` at model files from a source you don't
trust.** The requirements files are exact-pinned (see "Install dependencies"), so a fresh install reproduces
the tested set rather than drifting to whatever is newest: a finding means bumping the affected
pin deliberately, in a fresh venv, and re-testing — not upgrading packages in place.

**Before serving this over HTTPS:** set `SESSION_COOKIE_SECURE=true` in `backend/.env`. It defaults to `false` on purpose — a `Secure` cookie is silently dropped by the browser on plain `http://localhost`, which would make login look like it does nothing — but left `false` in production the session cookie can leak over plain http. Also add the real dashboard origin to `CORS_ORIGINS` in `backend/.env` (a **JSON list**, e.g. `["https://dashboard.example.com"]` — a comma-separated value fails to parse and the app won't start), which both CORS and the CSRF check read.

## Configuration reference

Every setting can be overridden through an environment variable or `backend/.env`; each one, with its
default and meaning, is documented in [`backend/.env.example`](.env.example). Two easy-to-miss facts:
`CORS_ORIGINS` must be a **JSON list**, and the file-location settings (`ARTIFACTS_DIR`, `FEEDBACK_STORE`,
...) default to paths inside this repo.

## Database migrations

`Base.metadata.create_all` only creates *missing tables* — it never alters one that already exists — so
a column or constraint added to a model later would never reach a database created earlier. There's no
Alembic here; instead `app/migrations.py` runs at every startup, applies the few schema changes that
matter to an existing database, and does nothing on a current one (each step first inspects the live
schema). It currently:

- adds `alerts.feature_schema_version` and backfills it for every existing alert from that alert's own
  stored feature keys (exact, not a guess);
- adds a unique index on `feedback.alert_id`. This is the one step that deletes data: if the database
  already holds several feedback rows for one alert, only each alert's **newest** is kept (logged as a
  warning with the counts); rows already written to the retraining CSV are not touched.

Starting several workers at once against a database that still needs a migration is safe: whichever
worker loses the race sees "already exists" and carries on.

## Feedback: one label per alert

An alert has at most one validated label (unique constraint on `feedback.alert_id`). Submitting again
**updates** it: same label → nothing changes (idempotent); a corrected label → the alert's earlier row in
the retraining CSV is *replaced*, not joined by a contradictory second one. The CSV has no alert-id column
(its columns are exactly what `cyber_ai.train` reads), so the earlier row is found by content — the
alert's feature vector plus its old label. `created_at` on a feedback row is the time of its *current*
label.

## Feature schema versioning

Every alert records `feature_schema_version`: a short fingerprint of the set of feature names it was
scored under (returned by `GET /api/alerts/{id}`). `Alert.features` is keyed by feature name, so old rows
stay readable if the trained feature set changes; the version says *which* set a row belongs to. It's used
in one place: `POST /api/feedback` returns `409` for an alert scored under a different feature set than the
deployed model's, rather than writing a training row full of silently-imputed blanks — re-ingest the traffic
and give feedback on the fresh alert.

## Running with multiple workers

`uvicorn app.main:app --workers N` works, with these specifics (the default single-worker dev setup is
unaffected):

- **Model reload is shared.** After a retrain is accepted by the quality gate, *every* worker reloads the
  new model on its next request. The signal is a small marker file (`MODEL_GENERATION_FILE`, default
  `<repo>/.model_generation`); each worker compares it with the value its loaded model was read under.
  It is deliberately not derived from the model files' modification times: the retrain overwrites
  `artifacts/` in place while training and only afterwards decides whether the result may go live, so
  watching those files would hot-swap an unvetted model. Logged as `Model reloaded after a retrain in
  process <pid>`. Verified with two real worker processes.
- **Still per worker:** the login-lockout and chat rate limits (in-memory; a shared store such as Redis
  would be needed for true global limits), and the lock around the feedback CSV. The database is
  protected across workers by the unique constraint, but the CSV file has no cross-process lock, so two
  workers rewriting it at the same instant could lose a line. Feedback volume is tiny, so the practical
  advice is one worker for anything that writes feedback, or a real file lock if that ever changes.

## Tests

`backend/tests/` holds the pytest suite (`pip install -r backend/requirements-dev.txt`, then
`python -m pytest backend/tests`). It runs against an in-memory SQLite database and a stub model — no
MySQL, no `artifacts/` — except one test that spawns a real second process to check the cross-worker
reload. Currently covers the feedback upsert, feature-schema versioning, the startup migration (including
the multi-worker startup race), and the reload signal.

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
| `POST /api/ingest/csv` | Threat Hunter, Administrator | Upload a traffic CSV, score it, store alerts. Idempotent: the same file (same name + bytes) sent again stores nothing new; `allow_duplicates=true` opts out (for deliberate replays) |
| `POST /api/ingest/demo` | Threat Hunter, Administrator | Score the repo's curated `demo/panel_demo_traffic.csv` (no upload needed — handy for testing/demos) |
| `GET /api/alerts` | Any role | List alerts, filterable by `risk_level`, `category`, `source_file`, `batch_id`, paginated |
| `GET /api/alerts/{id}` | Any role | Full alert detail incl. raw feature vector and SHAP explanations |
| `POST /api/alerts/{id}/chat` | Any role | Per-alert explainability chatbot, grounded in that alert's own data |
| `POST /api/chat` | Any role | General project/network-threat chatbot (not tied to an alert) |
| `GET /api/stats/summary` | Any role | Counts by risk level / category, for dashboard tiles |
| `GET /api/stats/timeseries` | Any role | Per-minute alert counts for the last N minutes, for a chart |
| `POST /api/feedback` | Security Analyst, Threat Hunter, Administrator | Analyst submits a validated label for an alert (one per alert — resubmitting updates it, see [Feedback](#feedback-one-label-per-alert)); writes the training row to `data/feedback/validated_traffic.csv` (same file `cyber_ai.train --feedback-csv` reads) |
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

The simulator sends `allow_duplicates=true` with every chunk. Ingest is idempotent by default
(see Notes below), but a replay — especially `--loop`, which re-sends the same chunks on every
pass — is *meant* to look like fresh traffic arriving, so it opts out of the duplicate check.

## Notes

- `POST /api/ingest/*` defaults to storing only Medium/High-risk windows (pass
  `include_all_windows=true` to store everything, which `/ingest/demo` does by default
  so the full demo narrative — including the quiet BENIGN stretches — is visible).
- Ingest is idempotent: re-sending the same file (same name and same bytes) stores nothing new —
  the response reports it as `duplicates_skipped` — so clicking "Score curated demo CSV" twice, or
  re-running a script, can't silently double every count. Identity is the pair (filename, SHA-256
  of the bytes), so a *different* file that happens to share a name, or one file sent as many
  chunks, is never mistaken for a duplicate. Re-sending the same file with `include_all_windows`
  turned on after a Medium/High-only pass adds just the Low windows the first pass skipped.
- `POST /api/retrain` runs `cyber_ai.train` as a background subprocess (it can take
  several minutes); poll `GET /api/retrain/{id}` for status. When the quality gate accepts the
  new model, every worker process reloads it on its next request — no server restart needed (see
  [Running with multiple workers](#running-with-multiple-workers)).
- Every route below `/api/health` requires a session -- see [Authentication](#authentication).
