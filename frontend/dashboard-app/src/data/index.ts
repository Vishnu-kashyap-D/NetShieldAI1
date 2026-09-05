import type { DataProvider } from "./DataProvider";
import { getDataMode } from "./config";
import { MockDataProvider } from "./mockProvider";
import { RealApiProvider } from "./realApiProvider";

export type { DataProvider, AlertListParams, TimeseriesParams, IngestParams } from "./DataProvider";
export * from "../types/api";
export { parseShapFeatures } from "./shap";
export { ApiUnavailableError, ApiRequestError, RetrainAlreadyRunningError, NotFoundError } from "./errors";
export { getDataMode, setDataMode, clearDataModeOverride, type DataMode } from "./config";
export { MockDataProvider } from "./mockProvider";
export { RealApiProvider } from "./realApiProvider";
export type { SimulatedWorkflowEvent } from "./mock/scenario";

let cached: DataProvider | null = null;
let cachedMode: string | null = null;

/**
 * Returns the active DataProvider for the current data mode (see src/data/config.ts).
 * Components should call this instead of constructing MockDataProvider / RealApiProvider
 * directly, so switching modes never requires touching component code.
 */
export function getDataProvider(): DataProvider {
  const mode = getDataMode();
  if (!cached || cachedMode !== mode) {
    cached = mode === "real" ? new RealApiProvider() : new MockDataProvider();
    cachedMode = mode;
  }
  return cached;
}

/** Forces the next getDataProvider() call to construct a fresh instance. Mainly useful in tests. */
export function resetDataProviderCache(): void {
  cached = null;
  cachedMode = null;
}
