import type {
  AlertDetailOut,
  AlertListOut,
  FeedbackIn,
  FeedbackOut,
  HealthOut,
  IngestSummaryOut,
  RetrainTriggerIn,
  RiskLevel,
  StatsSummaryOut,
  TimeseriesPointOut,
  TrainingRunOut,
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
}
