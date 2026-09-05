export type DataMode = "mock" | "real";

const STORAGE_KEY = "netshield.dataMode";
const DEFAULT_MODE: DataMode = "mock";
const DEFAULT_API_BASE_URL = "http://localhost:8000";

function isDataMode(value: string | null | undefined): value is DataMode {
  return value === "mock" || value === "real";
}

/**
 * Resolves which data provider to use. Priority: an explicit runtime override
 * (setDataMode, persisted to localStorage -- lets a future settings toggle flip
 * modes without a rebuild) beats the build-time VITE_DATA_MODE env var, which
 * beats the default ("mock"). Components never read this directly; they call
 * getDataProvider() from src/data/index.ts.
 */
export function getDataMode(): DataMode {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (isDataMode(stored)) return stored;
  } catch {
    // localStorage unavailable (SSR, privacy mode, etc.) -- fall through to env/default.
  }
  const fromEnv = import.meta.env.VITE_DATA_MODE;
  if (isDataMode(fromEnv)) return fromEnv;
  return DEFAULT_MODE;
}

/** Persists a runtime override for the data mode. Takes effect for providers created after this call. */
export function setDataMode(mode: DataMode): void {
  try {
    localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // localStorage unavailable -- override just won't persist across reloads.
  }
}

/** Clears any runtime override, falling back to VITE_DATA_MODE / the default. */
export function clearDataModeOverride(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // nothing to do
  }
}

/** Base URL of the FastAPI backend, used only by the real provider. */
export function getApiBaseUrl(): string {
  return import.meta.env.VITE_API_BASE_URL ?? DEFAULT_API_BASE_URL;
}
