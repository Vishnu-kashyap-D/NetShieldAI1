import type {
  AlertDetailOut,
  AlertListOut,
  ChatMessage,
  ChatOut,
  FeedbackIn,
  FeedbackOut,
  HealthOut,
  IngestSummaryOut,
  LoginIn,
  RetrainTriggerIn,
  RiskLevel,
  StatsSummaryOut,
  TimeseriesPointOut,
  TrainingRunOut,
  UserOut,
} from "../types/api";

/** Query params for listAlerts -- mirrors GET /api/alerts (backend/app/routers/alerts.py). */
export interface AlertListParams {
  risk_level?: RiskLevel;
  category?: string;
  source_file?: string;
  batch_id?: string;
  /** Default 50, max 500 (enforced server-side for the real provider). */
  limit?: number;
  offset?: number;
}

/** Query params for getTimeseries -- mirrors GET /api/stats/timeseries. */
export interface TimeseriesParams {
  /** How many minutes of history to bucket. Default 60. */
  minutes?: number;
  /** Bucket width in seconds. Default 30. */
  bucket_seconds?: number;
}

/** Query params shared by ingestDemo / ingestCsv -- mirrors POST /api/ingest/*. */
export interface IngestParams {
  include_all_windows?: boolean;
  shap?: boolean;
}

/**
 * The single contract both the mock/demo provider and the real API provider
 * implement. React components (and any future data-fetching hooks) must depend
 * on this interface -- never import a provider implementation directly.
 *
 * Every method here maps 1:1 to an existing backend endpoint (see
 * backend/app/routers/*.py). No method here invents a backend capability that
 * doesn't already exist.
 */
export interface DataProvider {
  /** "mock" for the demo/mock provider, "real" for the live-API provider. */
  readonly mode: "mock" | "real";

  /**
   * A short disclaimer string to surface in the UI while in mock mode (e.g.
   * "Demo data -- not live model output"), or null in real mode. Exists so
   * mock/demo data is always clearly identifiable to whoever is looking at it.
   */
  getDataSourceNotice(): string | null;

  /** GET /api/health */
  getHealth(): Promise<HealthOut>;

  /** GET /api/alerts */
  listAlerts(params?: AlertListParams): Promise<AlertListOut>;

  /** GET /api/alerts/{id} */
  getAlert(id: number): Promise<AlertDetailOut>;

  /** GET /api/stats/summary */
  getStatsSummary(): Promise<StatsSummaryOut>;

  /** GET /api/stats/timeseries */
  getTimeseries(params?: TimeseriesParams): Promise<TimeseriesPointOut[]>;

  /** POST /api/ingest/demo */
  ingestDemo(params?: IngestParams): Promise<IngestSummaryOut>;

  /** POST /api/ingest/csv (multipart file upload) */
  ingestCsv(file: File, params?: IngestParams): Promise<IngestSummaryOut>;

  /** POST /api/feedback */
  submitFeedback(payload: FeedbackIn): Promise<FeedbackOut>;

  /** GET /api/feedback */
  listFeedback(): Promise<FeedbackOut[]>;

  /**
   * POST /api/retrain
   * @throws RetrainAlreadyRunningError if a run is already in progress (mirrors the real backend's HTTP 409).
   */
  triggerRetrain(payload?: RetrainTriggerIn): Promise<TrainingRunOut>;

  /** GET /api/retrain */
  listRetrainRuns(): Promise<TrainingRunOut[]>;

  /**
   * GET /api/retrain/{id}
   * @throws NotFoundError if no run with this id exists.
   */
  getRetrainRun(id: number): Promise<TrainingRunOut>;

  /**
   * POST /api/alerts/{id}/chat -- the explainability chatbot for one alert. `history` is this
   * conversation's prior turns, oldest first (used only for multi-turn LLM context; deterministic
   * answers are always stateless). Grounded entirely in that alert's own stored data -- never
   * performs a new prediction and never reasons about any other alert.
   * @throws NotFoundError if no alert with this id exists.
   */
  askAboutAlert(alertId: number, question: string, history?: ChatMessage[]): Promise<ChatOut>;

  /**
   * POST /api/chat -- the sidebar's "SHAP" page. Unlike askAboutAlert, this is NOT grounded in
   * any one alert; it only answers questions about this project or general network-threat
   * topics (backend/app/chat_service.py::answer_project_question), refusing anything else.
   */
  askProjectQuestion(question: string, history?: ChatMessage[]): Promise<ChatOut>;

  /**
   * POST /api/auth/login. Real mode: verifies credentials against the backend and sets the
   * session cookie; throws on a wrong email/password. Mock mode: cosmetic (matches the old
   * "any password signs you in" demo behavior) -- accepts any input and echoes it back as the
   * signed-in identity, never contacting a server.
   */
  login(payload: LoginIn): Promise<UserOut>;

  /** POST /api/auth/logout in real mode (clears the session cookie server-side); a no-op in mock mode. */
  logout(): Promise<void>;

  /**
   * GET /api/auth/me in real mode -- used on app load to check whether an existing session
   * cookie is still valid (returns null, not a throw, if there's no session or it expired).
   * Mock mode always returns null; the mock session's own persistence is handled entirely by
   * SessionProvider's sessionStorage logic, not this method.
   */
  getCurrentUser(): Promise<UserOut | null>;
}
