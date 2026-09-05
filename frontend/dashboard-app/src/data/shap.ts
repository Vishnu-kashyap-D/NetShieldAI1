import type { ShapDirection, ShapFeature } from "../types/api";

const VALID_DIRECTIONS: readonly ShapDirection[] = ["positive", "negative", "neutral", "unknown"];

/**
 * Parses the JSON string the backend stores in `top_classifier_features` /
 * `top_anomaly_features` (see cyber_ai/explain.py::_top_features) into a typed
 * array. Returns [] for null/empty/unparseable input rather than throwing --
 * both are legitimate "no explanation available" states (Low-risk alerts never
 * get SHAP explanations, and alerts scored without shap=true never do either).
 *
 * Tolerant of the pre-signed-SHAP shape ({feature, mean_abs_shap} only, no
 * shap_value/direction) -- those entries parse with shap_value left undefined
 * and direction normalized to "unknown", never assumed to be positive/negative/neutral.
 */
export function parseShapFeatures(raw: string | null): ShapFeature[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(
        (entry): entry is Record<string, unknown> =>
          typeof entry === "object" &&
          entry !== null &&
          typeof (entry as Record<string, unknown>).feature === "string" &&
          typeof (entry as Record<string, unknown>).mean_abs_shap === "number",
      )
      .map((entry) => ({
        feature: entry.feature as string,
        mean_abs_shap: entry.mean_abs_shap as number,
        shap_value: typeof entry.shap_value === "number" ? entry.shap_value : undefined,
        direction: VALID_DIRECTIONS.includes(entry.direction as ShapDirection)
          ? (entry.direction as ShapDirection)
          : "unknown",
      }));
  } catch {
    return [];
  }
}
