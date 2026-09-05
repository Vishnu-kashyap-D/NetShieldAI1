import "./TrainingMetrics.css";

/**
 * Renders TrainingRunOut.metrics generically -- that field is `Record<string, unknown>`
 * on the backend (whatever cyber_ai.train's training_metrics.json happens to contain,
 * see backend/app/routers/retrain.py), with no fixed schema documented. Rather than
 * hardcoding specific keys (accuracy, F1, etc.) that may not actually be present,
 * this walks whatever structure comes back and displays it as nested key/value rows.
 */
export function TrainingMetrics({ metrics }: { metrics: Record<string, unknown> }) {
  return (
    <div className="training-metrics">
      <MetricsGroup entries={Object.entries(metrics)} depth={0} />
    </div>
  );
}

function MetricsGroup({ entries, depth }: { entries: [string, unknown][]; depth: number }) {
  return (
    <div className="training-metrics-group" style={{ paddingLeft: depth > 0 ? 16 : 0 }}>
      {entries.map(([key, value]) => {
        const isNestedObject = value !== null && typeof value === "object" && !Array.isArray(value);
        return (
          <div
            className={`training-metrics-row${isNestedObject ? " training-metrics-row--nested" : ""}`}
            key={key}
          >
            <span className="training-metrics-key">{key}</span>
            {isNestedObject ? (
              <MetricsGroup entries={Object.entries(value as Record<string, unknown>)} depth={depth + 1} />
            ) : (
              <span className="training-metrics-value">{formatValue(value)}</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "Not available";
  if (Array.isArray(value)) return value.length === 0 ? "[]" : value.map(formatValue).join(", ");
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(4);
  if (typeof value === "boolean") return value ? "true" : "false";
  return String(value);
}
