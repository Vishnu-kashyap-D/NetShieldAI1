import type { AlertDetailOut } from "../types/api";

/** Metadata columns, in the same order the fields appear on the alert detail page. */
const METADATA_COLUMNS: Array<[label: string, get: (alert: AlertDetailOut) => string | number | boolean | null]> = [
  ["id", (a) => a.id],
  ["batch_id", (a) => a.batch_id],
  ["window_start", (a) => a.window_start],
  ["window_end", (a) => a.window_end],
  ["source_file", (a) => a.source_file],
  ["ingested_at", (a) => a.ingested_at],
  ["actual_label", (a) => a.actual_label],
  ["actual_category", (a) => a.actual_category],
  ["predicted_label", (a) => a.predicted_label],
  ["pipeline_action", (a) => a.pipeline_action],
  ["risk_level", (a) => a.risk_level],
  ["risk_score", (a) => a.risk_score],
  ["confidence", (a) => a.confidence],
  ["is_anomaly", (a) => a.is_anomaly],
  ["anomaly_score", (a) => a.anomaly_score],
  ["anomaly_threshold", (a) => a.anomaly_threshold],
];

function csvEscape(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * Builds a single-row CSV for one alert: the same metadata shown on its detail page, plus its
 * full 76-column feature vector -- deliberately the same column shape as the feedback CSV
 * (data/feedback/validated_traffic.csv) this project already produces elsewhere, so the file is
 * directly comparable/reusable, not a one-off format invented just for this export.
 */
export function alertToCsv(alert: AlertDetailOut): string {
  const featureNames = Object.keys(alert.features);
  const header = [...METADATA_COLUMNS.map(([label]) => label), ...featureNames];
  const row = [
    ...METADATA_COLUMNS.map(([, get]) => csvEscape(get(alert))),
    ...featureNames.map((name) => csvEscape(alert.features[name])),
  ];
  return `${header.map(csvEscape).join(",")}\n${row.join(",")}\n`;
}

/** Triggers a browser download of `content` as `filename` -- no server round trip needed. */
export function downloadTextFile(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function exportAlertAsCsv(alert: AlertDetailOut): void {
  downloadTextFile(`netshield-alert-${alert.id}.csv`, alertToCsv(alert), "text/csv;charset=utf-8");
}
