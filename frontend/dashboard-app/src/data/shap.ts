import type { ShapFeature } from "../types/api";

/**
 * Parses the JSON string the backend stores in `top_classifier_features` /
 * `top_anomaly_features` (see cyber_ai/explain.py::_top_features) into a typed
 * array. Returns [] for null/empty/unparseable input rather than throwing --
 * both are legitimate "no explanation available" states (Low-risk alerts never
 * get SHAP explanations, and alerts scored without shap=true never do either).
 */
export function parseShapFeatures(raw: string | null): ShapFeature[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (entry): entry is ShapFeature =>
        typeof entry === "object" &&
        entry !== null &&
        typeof (entry as ShapFeature).feature === "string" &&
        typeof (entry as ShapFeature).mean_abs_shap === "number",
    );
  } catch {
    return [];
  }
}
