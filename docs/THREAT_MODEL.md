# NetShield AI — Threat Model (of the product itself)

NetShield watches other people's networks, so it is itself a high-value target: whoever controls it can blind it, poison it, or read what it sees. This page lists **what an attacker could go after, how they could reach it, what stops them today, and what is still open.** It is written from the code as it stands (mitigations were checked against the test-suite in `backend/tests/`), not from intent.

**Scope:** the FastAPI backend, its MySQL database, the model files in `artifacts/`, the training/feedback loop, the two chatbots, and the browser dashboard's use of the API. **Out of scope:** the hosts NetShield monitors, the network it is deployed on, and the operating system.

**Deployment assumption:** a small team, one backend process (or a few workers), served to browsers over HTTPS behind a reverse proxy, with the database and `artifacts/` on the same trust zone as the backend.

---

## 1. What is worth protecting

| Asset | Why it matters |
|---|---|
| **Model files** (`artifacts/*.keras`, `preprocessing.joblib`) | Whoever can replace them controls every verdict. `preprocessing.joblib` is a pickle: loading a tampered one runs attacker code. |
| **Training feedback** (`data/feedback/validated_traffic.csv`) | It is what the next model learns from — an attacker who can add wrong labels can teach it to ignore an attack. |
| **User accounts & sessions** | Roles gate ingest, feedback, retraining and user management. |
| **Alert database** | Flow statistics about a monitored network (no payloads or IP addresses, so moderate sensitivity). |
| **Secrets** (`backend/.env`: DB password, Gemini API key) | Direct database access; spend on a paid LLM. |
| **Availability** | An IDS that can be knocked over quietly is worse than none. |

## 2. Trust boundaries & entry points

```
 Browser (analyst) ──HTTPS──▶ reverse proxy ──▶ FastAPI ──▶ MySQL
                                                   │  ├──▶ artifacts/ (Keras + pickle, local disk)
 Scripts (stream simulator, live capture) ─────────┤  ├──▶ feedback CSV ──▶ retrain subprocess ──▶ artifacts/
                                                   │  └──▶ Gemini API (third party, chat only)
 Uploaded CSV (untrusted content) ─────────────────┘
```

Entry points an outsider or low-privilege user can touch: **login**, every authenticated **API route**, **CSV upload**, **chat text**, **feedback labels/notes**, and the **browser** the analyst is signed in with.

---

## 3. Threats, mitigations and what is left

Severity is my judgement of *residual* risk after the mitigation, for the assumed deployment.

### 3.1 Access control

| Threat | Mitigation in place | Residual | Sev. |
|---|---|---|---|
| Guessing passwords | bcrypt hashes; lockout after 5 failures per (address, email) and 20 per address, → `429` + `Retry-After`; only failures count; `X-Forwarded-For` is *not* trusted so it can't be spoofed to dodge the limit | Limits are **in memory and per worker** (reset on restart; N workers = N× the budget). Behind a proxy every user shares the proxy's address until proxy handling is configured, so the 20-per-address limit could lock *everyone* out. No MFA. | Med |
| Account enumeration | Same message for "no such user" and "wrong password" | **Timing:** an unknown email skips the bcrypt check, so it answers measurably faster than a wrong password on a real account. | Low |
| Well-known default credentials | Seeding happens only on an empty `users` table | The four demo accounts share one password **printed in the README**. There is no password-change or delete-account endpoint yet. **Do not expose a deployment that still has them.** | **High if forgotten** |
| Stealing a session token from the database | Only `sha256(token)` is stored; the raw token lives only in the cookie | — | Low |
| Stealing the cookie in the browser | `HttpOnly`; `SameSite=Lax`; 7-day TTL; logout deletes the row | **`Secure` is off by default** (dev over http) — must be `SESSION_COOKIE_SECURE=true` under HTTPS. Expired-but-never-revisited session rows are only purged lazily. | Med until set |
| Privilege escalation | Role is a server-side fact on the account, never supplied by the client; every gated route checks role after authenticating (`401` before `403`); tested for all 4 roles × 9 actions | Coarse RBAC only; no audit log of who did what beyond feedback and retrain rows | Low |
| Feedback authorship forged | — | `analyst` on a feedback row is **client-supplied**, unlike a retrain's `triggered_by` (taken from the session). An analyst can attribute a label to someone else. | Low |

### 3.2 Web-application attacks

| Threat | Mitigation | Residual | Sev. |
|---|---|---|---|
| CSRF (a malicious page makes the signed-in browser act) | Every `POST/PUT/PATCH/DELETE` carrying an `Origin`/`Referer` must match the allow-list or the server itself, else `403`; `SameSite=Lax` alone is *not* enough (same-site ignores ports — reproduced and fixed). Scripts sending neither header pass, since CSRF needs a browser. | The allow-list (`CORS_ORIGINS`) must list the real dashboard origin and nothing broader | Low |
| Clickjacking, MIME sniffing, caching of per-user data | `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`; on `/api/*` a `default-src 'none'` CSP and `Cache-Control: no-store`; HSTS over HTTPS | — | Low |
| XSS | API returns JSON only; the React front end escapes by default; CSP on `/api/*` | The dashboard's own CSP was not audited | Low |
| Information disclosure | Errors are generic; passwords/hashes never returned | Unauthenticated **`GET /api/health`** returns the absolute `artifacts_dir` and, when degraded, the raw exception text | Low |

### 3.3 Untrusted input

| Threat | Mitigation | Residual | Sev. |
|---|---|---|---|
| Malformed / binary / oversized CSV | Size cap (`MAX_UPLOAD_BYTES`, 200 MB) checked from the declared length and again after reading; parse failures return `422`, never `500`; too-short files rejected | The whole upload is read into memory. Scoring runs **inside the async handler, so a big scoring job blocks the server's event loop** for its duration (Threat Hunter or Administrator only). | Med |
| Prompt injection via the CSV's `Label` column (it later lands in the chatbot's LLM prompt) | Labels outside the known vocabulary are stored as `Unrecognized` | Feedback `validated_label` and `notes` are free text and are not vocabulary-checked | Low |
| Re-ingest flooding the database | Ingest is idempotent per (filename, SHA-256) | `allow_duplicates=true` deliberately opts out (used by the replay simulator) | Low |
| Injection into the retrain command | Command is built from server config only — no request data reaches it | — | Low |
| Oversized or floods of chat input | Question ≤ 2,000 chars, history ≤ 40 turns, message ≤ 8,000 chars; 20 requests/min per user across both bots | Per-process counter, like the login limit | Low |

### 3.4 The ML pipeline itself (the part specific to this product)

| Threat | Mitigation | Residual | Sev. |
|---|---|---|---|
| **Data poisoning** — wrong feedback labels teach the next model to ignore an attack | Only Security Analyst+ can submit; one label per alert; **retraining is Administrator-only and manual**; a **quality gate** rejects a model whose BiLSTM accuracy or Autoencoder balanced accuracy drops by more than 0.01 and restores the previous files | The gate judges *headline* metrics on data that already includes the feedback, so a **targeted** poisoning that leaves the averages intact (e.g. one attack type) can pass. A malicious or compromised analyst is the realistic route. Review the feedback log before retraining. | **Med** |
| **Evasion** — traffic shaped to score under the Autoencoder threshold | — | Detection is per 10-row window; the sequential gate already misses ~44 % of attack windows in evaluation. Adversarial robustness has **not** been tested (planned, Phase 6). Slow, patient attacks spread across windows are not correlated. | **High (inherent)** |
| **Model swap** — replacing `artifacts/` files, including the pickled `preprocessing.joblib` (code execution on load) | Files are only ever produced by our own training; docs say never load artifacts from an untrusted source; the rejected-run restore keeps the last good copy | Depends entirely on **filesystem permissions**: whoever can write `artifacts/` owns the server. No signature or hash check on load. | Med |
| Unreliable classes presented as fact | The runbook and this page flag them | *Data Exfiltration* rests on ~36 dataset rows; the UI does not yet warn (planned, 6.7) | Med |
| Concept drift silently degrading detection | — | No live monitoring of score distributions (planned, 6.5) | Med |

### 3.5 Third parties & supply chain

| Threat | Mitigation | Residual | Sev. |
|---|---|---|---|
| Alert data leaving the system | Only the chatbots call out (Gemini); per-alert context is limited to that alert's own scores, SHAP values and feature values — no credentials, no other alerts (tested); with no API key configured nothing leaves | With a key set, that alert data **is sent to a third-party LLM** — a policy decision for the operator | Med |
| Vulnerable dependencies | Both requirement files are exact-pinned; `pip-audit` / `npm audit` procedure documented; the load-bearing scikit-learn pin is explained | Audits are manual (no CI); Keras advisories concern untrusted model files, which we never load | Low |
| Secrets in the repository | `backend/.env` is git-ignored; `.env.example` holds placeholders only | Secrets on disk in plaintext | Low |
| Multi-worker inconsistencies | Model reload is shared through a marker file; the DB has a unique constraint on feedback | The feedback CSV has no cross-process lock: keep to one worker for anything that writes feedback | Low |

---

## 4. Priorities

**Before any real (non-demo) deployment**
1. Remove the seeded demo accounts; create real ones. *(needs a password-change / delete-account path)*
2. `SESSION_COOKIE_SECURE=true`, real `CORS_ORIGINS`, serve over HTTPS.
3. Lock down write access to `artifacts/` and `data/feedback/` to the service account only.
4. Decide, as a policy, whether alert data may go to the LLM provider; leave `GEMINI_API_KEY` unset if not.

**Worth fixing next (small, code)**
5. Take `analyst` from the session on feedback (as retrain already does).
6. Run scoring off the event loop (or make the ingest route a plain `def`) so one upload can't stall the API.
7. Trim `/api/health` for unauthenticated callers (drop the path and exception text).
8. Equalise login timing for unknown emails (hash a dummy password).

**Larger, already on the plan**
9. Shared rate-limit store (Redis) before running several workers; adversarial-robustness and drift monitoring (Phase 6).

---

## 5. Evidence

The controls marked "tested" above are exercised by `python -m pytest backend/tests` — role matrix (4 roles × 9 actions), login lockout, session hashing/expiry, CSRF origin checks, security headers, upload limits, the retrain concurrency guard and quality gate, and chat limits. As a check that those tests bite, each of a dozen key rules (retrain role, 409 guard, quality gate, CSRF check, lockout counting, session hashing, ingest dedup, label sanitising, …) was deliberately broken in turn and the suite failed every time.
