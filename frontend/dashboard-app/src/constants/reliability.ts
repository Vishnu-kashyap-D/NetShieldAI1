import { UNKNOWN_CATEGORY } from "./taxonomy";

/**
 * Categories whose model output should not be taken at face value, and why. Keep in step with
 * `data.low_sample_categories` in reports/training_metrics.json (cyber_ai.train flags any category with
 * fewer than 200 raw samples): Data Exfiltration is the CICIDS2017 "Infiltration" label, and the whole
 * dataset holds only 36 rows of it -- one window in the held-out test set -- so neither its precision nor
 * its recall means anything.
 */
export const UNRELIABLE_CATEGORIES: Readonly<Record<string, string>> = {
  "Data Exfiltration":
    "Statistically unreliable: the training data contains only ~36 examples of this category (1 window in the held-out test set), so the model's call on it can't be trusted. Verify by hand.",
};

export const UNKNOWN_EXPLANATION =
  "The Autoencoder flagged this window as anomalous, but the classifier wasn't confident enough to name a known attack category. Treat it as an unclassified anomaly and investigate the evidence.";

/** Plain-text warning for a predicted category, or null when it can be taken at face value. */
export function reliabilityWarning(label: string): string | null {
  if (UNRELIABLE_CATEGORIES[label]) return UNRELIABLE_CATEGORIES[label];
  if (label === UNKNOWN_CATEGORY) return UNKNOWN_EXPLANATION;
  return null;
}
