// TypeScript mirror of backend/app/schemas.py (+ backend/app/models.py for the
// `features` JSON column). Field names intentionally match the backend's JSON
// responses exactly (snake_case) so both data providers can share these types
// with no field-renaming/mapping layer in between.
//
// Source of truth: backend/app/schemas.py, backend/app/models.py,
// backend/app/routers/*.py, cyber_ai/data.py (ATTACK_CATEGORY_MAP / NORMAL_DECISION_LABEL).

/** Values of `risk_level`. Low = green, Medium = amber, High = red (project convention). */
export type RiskLevel = "Low" | "Medium" | "High";

/**
 * Values of `predicted_label` / `actual_category`. "Normal" is
 * cyber_ai.data.NORMAL_DECISION_LABEL; the six attack categories are the keys of
 * cyber_ai.data.ATTACK_CATEGORY_MAP (rolled up from the raw CICIDS2017 labels).
 */
export type AttackCategory =
  | "Normal"
  | "DoS / DDoS"
  | "Port Scanning"
  | "Brute Force"
  | "Botnet Activity"
  | "Malware Traffic"
  | "Data Exfiltration";

/** Status values of a `training_runs` row. */
export type RetrainStatus = "running" | "completed" | "failed";

/** Which way a signed SHAP value points -- see cyber_ai/explain.py::SHAP_DIRECTION_MEANING. */
export type ShapDirection = "positive" | "negative" | "neutral" | "unknown";

/**
 * One entry of a parsed `top_classifier_features` / `top_anomaly_features` list.
 * The backend stores these as a JSON *string* (see AlertOut below); this is the
 * shape of each element once parsed, per cyber_ai/explain.py::_top_features.
 *
 * `shap_value`/`direction` are optional because an alert scored before the signed-SHAP
 * change shipped only ever wrote `mean_abs_shap` -- those older rows parse with `shap_value`
 * undefined and `direction` "unknown" rather than crashing or assuming a sign.
 */
export interface ShapFeature {
  feature: string;
  /** Signed mean SHAP contribution over the window. Undefined for pre-signed-SHAP rows. */
  shap_value?: number;
  /** Unsigned mean |SHAP| -- magnitude/importance regardless of direction. Used for ranking. */
  mean_abs_shap: number;
  direction?: ShapDirection;
}

/** One turn of a chat conversation, oldest first -- mirrors backend/app/schemas.py::ChatMessageIn. */
export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

/** POST /api/alerts/{id}/chat request body. */
export interface ChatIn {
  question: string;
  history?: ChatMessage[];
}

/** Which parts of the alert's data actually informed a chat answer. */
export interface ChatSources {
  prediction: boolean;
  shap: boolean;
  feature_values: boolean;
  glossary: boolean;
}

/** POST /api/alerts/{id}/chat response. */
export interface ChatOut {
  answer: string;
  sources: ChatSources;
}

/** The raw 76-value standardized feature vector stored on an alert (feature name -> value). */
export type FeatureVector = Record<string, number | null>;

/** The four roles backend/app/auth.py::Role defines. Assigned server-side at account creation --
 * never chosen by the client at login. Must match those string values exactly. */
export type UserRole = "Viewer" | "Security Analyst" | "Threat Hunter" | "Administrator";

/** GET /api/auth/me, and the response of POST /api/auth/login and POST /api/auth/users. */
export interface UserOut {
  id: number;
  name: string;
  email: string;
  role: UserRole;
}

/** POST /api/auth/login request body. */
export interface LoginIn {
  email: string;
  password: string;
}

/** POST /api/auth/users request body (Administrator-only). */
export interface RegisterIn {
  name: string;
  email: string;
  password: string;
  role: UserRole;
}

/** GET /api/health */
export interface HealthOut {
  status: string;
  model_loaded: boolean;
  feature_count: number | null;
  artifacts_dir: string;
}

/** One row of the `alerts` table, as returned by GET /api/alerts. */
export interface AlertOut {
  id: number;
  batch_id: string;
  window_start: number;
  window_end: number;
  source_file: string;
  actual_label: string | null;
  actual_category: AttackCategory | null;
  predicted_label: AttackCategory;
  confidence: number;
  anomaly_score: number;
  anomaly_threshold: number;
  is_anomaly: boolean;
  pipeline_action: string;
  risk_score: number;
  risk_level: RiskLevel;
  /** JSON-encoded ShapFeature[], or null. Only populated for Medium/High alerts scored with shap=true. */
  top_classifier_features: string | null;
  /** JSON-encoded ShapFeature[], or null. Only populated for Medium/High alerts scored with shap=true. */
  top_anomaly_features: string | null;
  /** ISO 8601 timestamp string. */
  ingested_at: string;
}

/** GET /api/alerts/{id} — AlertOut plus the full raw feature vector. */
export interface AlertDetailOut extends AlertOut {
  features: FeatureVector;
}

/** GET /api/alerts response envelope. */
export interface AlertListOut {
  total: number;
  limit: number;
  offset: number;
  items: AlertOut[];
}

/** POST /api/ingest/csv and POST /api/ingest/demo response. */
export interface IngestSummaryOut {
  batch_id: string;
  source: string;
  windows_scored: number;
  anomalous_windows: number;
  alerts_written: number;
  risk_level_counts: Record<string, number>;
  predicted_label_counts: Record<string, number>;
}

/** GET /api/stats/summary */
export interface StatsSummaryOut {
  total_alerts: number;
  risk_level_counts: Record<string, number>;
  category_counts: Record<string, number>;
  anomaly_count: number;
}

/** One bucket of GET /api/stats/timeseries. */
export interface TimeseriesPointOut {
  /** ISO 8601 timestamp string (bucket start). */
  bucket: string;
  count: number;
  high: number;
  medium: number;
  low: number;
}

/** POST /api/feedback request body. */
export interface FeedbackIn {
  alert_id: number;
  validated_label: string;
  analyst?: string | null;
  notes?: string | null;
}

/** POST /api/feedback response, and each item of GET /api/feedback. */
export interface FeedbackOut {
  id: number;
  alert_id: number;
  validated_label: string;
  analyst: string | null;
  written_to_feedback_store: boolean;
  /** ISO 8601 timestamp string. */
  created_at: string;
}

/** POST /api/retrain request body. */
export interface RetrainTriggerIn {
  triggered_by?: string | null;
}

/** POST /api/retrain response, and each item of GET /api/retrain / GET /api/retrain/{id}. */
export interface TrainingRunOut {
  id: number;
  status: RetrainStatus;
  triggered_by: string | null;
  feedback_rows_used: number | null;
  metrics: Record<string, unknown> | null;
  error: string | null;
  /** ISO 8601 timestamp string. */
  started_at: string;
  /** ISO 8601 timestamp string, or null while still running. */
  finished_at: string | null;
}
