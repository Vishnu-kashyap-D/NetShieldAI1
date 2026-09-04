import type { DataProvider, AlertListParams, IngestParams, TimeseriesParams } from "./DataProvider";
import type {
  AlertDetailOut,
  AlertListOut,
  FeedbackIn,
  FeedbackOut,
  HealthOut,
  IngestSummaryOut,
  RetrainTriggerIn,
  StatsSummaryOut,
  TimeseriesPointOut,
  TrainingRunOut,
} from "../types/api";
import { getApiBaseUrl } from "./config";
import { ApiRequestError, ApiUnavailableError, NotFoundError, RetrainAlreadyRunningError } from "./errors";

function toQuery(params: object | undefined): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

/**
 * Talks to the real FastAPI backend (backend/app/main.py mounts every router under
 * /api). Every method here is a thin, faithful wrapper around one existing endpoint --
 * this provider does not add, rename, or reshape anything the backend doesn't already do.
 *
 * On this development machine the backend requires a running MySQL instance and
 * trained model artifacts under artifacts/ to serve most endpoints; if either is
 * missing, requests will fail (see the Phase 2 report for what's actually available
 * here). getHealth() degrades gracefully to an "unreachable" status instead of
 * throwing, mirroring how the backend itself reports a degraded (not crashed) state
 * when its model fails to load; every other method rejects with a typed error
 * (ApiUnavailableError / ApiRequestError) for the caller to handle.
 */
export class RealApiProvider implements DataProvider {
  readonly mode = "real" as const;

  private readonly baseUrl: string;

  constructor(baseUrl: string = getApiBaseUrl()) {
    this.baseUrl = baseUrl;
  }

  getDataSourceNotice(): string | null {
    return null;
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, init);
    } catch (cause) {
      throw new ApiUnavailableError(
        `Could not reach the NetShield backend at ${this.baseUrl}. Is it running?`,
        cause,
      );
    }

    if (!response.ok) {
      let detail: unknown;
      try {
        detail = await response.json();
      } catch {
        detail = undefined;
      }

      if (response.status === 404) {
        throw new NotFoundError(
          typeof detail === "object" && detail && "detail" in detail
            ? String((detail as { detail: unknown }).detail)
            : `Not found: ${path}`,
        );
      }
      throw new ApiRequestError(`Request to ${path} failed with status ${response.status}`, response.status, detail);
    }

    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  async getHealth(): Promise<HealthOut> {
    try {
      return await this.request<HealthOut>("/api/health");
    } catch (error) {
      if (error instanceof ApiUnavailableError) {
        return {
          status: `unreachable: ${error.message}`,
          model_loaded: false,
          feature_count: null,
          artifacts_dir: "",
        };
      }
      throw error;
    }
  }

  listAlerts(params?: AlertListParams): Promise<AlertListOut> {
    return this.request<AlertListOut>(`/api/alerts${toQuery(params)}`);
  }

  getAlert(id: number): Promise<AlertDetailOut> {
    return this.request<AlertDetailOut>(`/api/alerts/${id}`);
  }

  getStatsSummary(): Promise<StatsSummaryOut> {
    return this.request<StatsSummaryOut>("/api/stats/summary");
  }

  getTimeseries(params?: TimeseriesParams): Promise<TimeseriesPointOut[]> {
    return this.request<TimeseriesPointOut[]>(`/api/stats/timeseries${toQuery(params)}`);
  }

  ingestDemo(params?: IngestParams): Promise<IngestSummaryOut> {
    return this.request<IngestSummaryOut>(`/api/ingest/demo${toQuery(params)}`, { method: "POST" });
  }

  ingestCsv(file: File, params?: IngestParams): Promise<IngestSummaryOut> {
    const formData = new FormData();
    formData.set("file", file);
    return this.request<IngestSummaryOut>(`/api/ingest/csv${toQuery(params)}`, {
      method: "POST",
      body: formData,
    });
  }

  submitFeedback(payload: FeedbackIn): Promise<FeedbackOut> {
    return this.request<FeedbackOut>("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  listFeedback(): Promise<FeedbackOut[]> {
    return this.request<FeedbackOut[]>("/api/feedback");
  }

  async triggerRetrain(payload?: RetrainTriggerIn): Promise<TrainingRunOut> {
    try {
      return await this.request<TrainingRunOut>("/api/retrain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload ?? {}),
      });
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 409) {
        const detail = error.detail;
        const match =
          typeof detail === "object" && detail && "detail" in detail
            ? /run (\d+)/.exec(String((detail as { detail: unknown }).detail))
            : null;
        throw new RetrainAlreadyRunningError(match ? Number(match[1]) : -1);
      }
      throw error;
    }
  }

  listRetrainRuns(): Promise<TrainingRunOut[]> {
    return this.request<TrainingRunOut[]>("/api/retrain");
  }

  getRetrainRun(id: number): Promise<TrainingRunOut> {
    return this.request<TrainingRunOut>(`/api/retrain/${id}`);
  }
}
