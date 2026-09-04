# NetShield AI — Security Console (React frontend)

A dark, SOC-style analyst console for NetShield AI's hybrid network intrusion
detection pipeline (Autoencoder + BiLSTM + SHAP + analyst feedback loop). Built
with React, TypeScript, and Vite.

This app is a separate frontend from `frontend/netshield-dashboard.html` (the
original static prototype, left untouched) — everything here is a from-scratch
React implementation against the FastAPI backend's real API contract.

## Running it

```bash
npm install
npm run dev
```

Opens at `http://localhost:5173`. Sign in with any name/password, or use
"Continue as demo analyst" — this is a cosmetic, session-only login (see
`src/auth/session.tsx`); there's no real credential verification yet.

Other scripts: `npm run build` (type-check + production bundle), `npm run
lint` (oxlint), `npm run preview` (serve the production build locally).

## DEMO/MOCK mode vs LIVE API mode

The app can run entirely on its own, without the FastAPI backend, or against
the real backend — the same UI code handles both. Every page reads data
through a single `DataProvider` interface (`src/data/DataProvider.ts`), with
two implementations:

- **`MockDataProvider`** (`src/data/mockProvider.ts`) — generates a realistic,
  in-memory dataset (285 alerts, deterministic across reloads) with no
  network calls at all. This is what DEMO MODE uses.
- **`RealApiProvider`** (`src/data/realApiProvider.ts`) — calls the actual
  FastAPI backend (`GET/POST /api/...`) with no mock fallback.

Switch between them from the toggle in the top header ("Demo" / "Live API"),
or set the default at build time — see **Environment variables** below. A
mode switch is instant (no page reload) and always clears any data from the
previous mode first, so LIVE API mode never shows stale demo numbers, and
DEMO mode never silently mixes in real data.

In LIVE API mode, every page expects the backend at the configured base URL
(`http://localhost:8000` by default — see the backend's own README for how to
run it: `cd backend && uvicorn app.main:app --reload --port 8000`). If it
isn't running, every section shows an honest "couldn't load" error instead of
crashing or falling back to mock data.

## Environment variables

Copy `.env.example` to `.env.local` to override either of these (both are
optional — sensible defaults are baked in):

| Variable | Default | Purpose |
|---|---|---|
| `VITE_DATA_MODE` | `mock` | Which provider to start in: `mock` or `real`. Overridden at runtime by the header toggle (persisted to `localStorage`). |
| `VITE_API_BASE_URL` | `http://localhost:8000` | Base URL the real provider calls. Only used in `real` mode. |

## Basic demo workflow

For a live presentation, DEMO MODE includes a **Demo Scenario** panel on the
Dashboard ("Run Demo Scenario"). It plays a scripted incident through the
mock provider's own `simulateLiveIncident()` — nothing here calls a second
simulation engine or claims to run the real Autoencoder/BiLSTM/SHAP pipeline:

1. Traffic received → an anomaly is flagged → classified into an attack
   category → risk calculated → a real mock alert is generated.
2. Once its explanation is ready, click through to that alert's detail page
   to see the same SHAP panels, metrics, and feedback form every alert has.
3. The scenario also submits one simulated analyst confirmation and triggers
   a simulated retraining run, so you can follow the whole loop end-to-end:
   **Alert → Investigation → SHAP → Feedback → Retraining → Training complete.**

Every simulated event is labeled as such in the UI. You can also walk through
any alert manually from the Alerts page — a handful of alerts in the base
dataset are guaranteed High-risk with SHAP available (e.g. **#243** Port
Scanning, **#249** DoS/DDoS, **#277** Brute Force), so the full investigation
flow is demonstrable without waiting on the scenario at all.

## Project structure

```
src/
  auth/           cosmetic demo session (login gate)
  data/           DataProvider interface, mock + real implementations, mock data generator
  components/     layout/, common/, dashboard/, alerts/, alertDetail/, retraining/
  pages/          Login, Dashboard, Alerts, AlertDetail, Feedback, Retraining, Placeholder
  hooks/          usePolledAsync (loading/error/success + polling)
  constants/      shared taxonomy (categories, risk levels)
  styles/         theme.css (design tokens shared across the app)
```

Components must always go through `getDataProvider()` / `useDataProvider()` —
never import `MockDataProvider` or `RealApiProvider` directly in a page or
component (the one sanctioned exception is a runtime `instanceof` check where
a feature, like the Demo Scenario panel, only exists in mock mode).

---

*Below: the original Vite template notes, kept for reference.*

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the Oxlint configuration

If you are developing a production application, we recommend enabling type-aware lint rules by installing `oxlint-tsgolint` and editing `.oxlintrc.json`:

```json
{
  "$schema": "./node_modules/oxlint/configuration_schema.json",
  "plugins": ["react", "typescript", "oxc"],
  "options": {
    "typeAware": true
  },
  "rules": {
    "react/rules-of-hooks": "error",
    "react/only-export-components": ["warn", { "allowConstantExport": true }]
  }
}
```

See the [Oxlint rules documentation](https://oxc.rs/docs/guide/usage/linter/rules) for the full list of rules and categories.
