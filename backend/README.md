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

## API surface

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Model-loaded status |
| `POST /api/ingest/csv` | Upload a traffic CSV, score it, store alerts |
| `POST /api/ingest/demo` | Score the repo's curated `demo/panel_demo_traffic.csv` (no upload needed — handy for testing/demos) |
| `GET /api/alerts` | List alerts, filterable by `risk_level`, `category`, `source_file`, `batch_id`, paginated |
| `GET /api/alerts/{id}` | Full alert detail incl. raw feature vector and SHAP explanations |
| `GET /api/stats/summary` | Counts by risk level / category, for dashboard tiles |
| `GET /api/stats/timeseries` | Per-minute alert counts for the last N minutes, for a chart |
| `POST /api/feedback` | Analyst submits a validated label for an alert; appends to `data/feedback/validated_traffic.csv` (same file `cyber_ai.train --feedback-csv` reads) |
| `GET /api/feedback` | List submitted feedback |
| `POST /api/retrain` | Kick off `cyber_ai.train` with accumulated feedback, in the background |
| `GET /api/retrain` / `GET /api/retrain/{id}` | Check retraining run status/metrics |

## Stream simulator

There's no live traffic feed yet, so `backend/scripts/stream_simulator.py` stands in for
one: it replays a CSV in small paced chunks against `POST /api/ingest/csv` instead of
scoring it all in one instant, so `/api/stats/timeseries` shows an actual trend and a
future dashboard would see alerts arrive over time rather than all at once.

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
- There's no stream simulator yet — `/ingest/demo` (or repeatedly calling `/ingest/csv`
  with slices of a CSV) is the current stand-in for "live" traffic until that piece exists.
