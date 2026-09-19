/**
 * Thrown by a DataProvider when the backend is configured but not reachable
 * (connection refused, DNS failure, timeout) -- distinct from the backend
 * responding with an HTTP error, which means it IS reachable.
 */
export class ApiUnavailableError extends Error {
  readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "ApiUnavailableError";
    this.cause = cause;
  }
}

/**
 * Thrown when the backend responds with a non-2xx status. Mirrors the
 * information a caller would get from the real FastAPI error response.
 */
export class ApiRequestError extends Error {
  readonly status: number;
  readonly detail?: unknown;

  constructor(message: string, status: number, detail?: unknown) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Thrown when a retrain is triggered while one is already running -- mirrors
 * the real backend's HTTP 409 from POST /api/retrain (backend/app/routers/retrain.py),
 * so calling code can handle this case the same way regardless of provider mode.
 */
export class RetrainAlreadyRunningError extends Error {
  readonly runId: number;

  constructor(runId: number) {
    super(`Training run ${runId} is already running.`);
    this.name = "RetrainAlreadyRunningError";
    this.runId = runId;
  }
}

/**
 * Thrown by a DataProvider for a lookup that doesn't exist -- mirrors the real
 * backend's HTTP 404 (alert not found, training run not found).
 */
export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

/**
 * The message worth showing a person for a failed request.
 *
 * The backend explains itself in its JSON body -- FastAPI's `{"detail": "..."}` for errors it
 * raises on purpose (429 "Try again in 42 seconds", 413 too-large upload, 401 "Incorrect email or
 * password"), or `{"detail": [{"msg": ...}, ...]}` for request-validation failures (422) -- but
 * ApiRequestError.message is only the generic "Request to /x failed with status N". Prefer the
 * backend's own words when there are any.
 */
export function describeApiError(err: unknown, fallback: string): string {
  if (err instanceof ApiRequestError) {
    const body = err.detail;
    if (typeof body === "object" && body !== null && "detail" in body) {
      const detail = (body as { detail: unknown }).detail;
      if (typeof detail === "string" && detail) return detail;
      if (Array.isArray(detail)) {
        const first = detail[0] as { msg?: unknown } | undefined;
        if (typeof first?.msg === "string") return first.msg;
      }
    }
    return err.message;
  }
  return err instanceof Error ? err.message : fallback;
}
