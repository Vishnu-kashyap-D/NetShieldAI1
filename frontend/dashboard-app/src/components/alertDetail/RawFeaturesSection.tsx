import type { FeatureVector } from "../../types/api";
import "./RawFeaturesSection.css";

function formatFeatureValue(value: number | null): string {
  if (value === null) return "—";
  return Number.isInteger(value) ? String(value) : value.toFixed(4);
}

/**
 * The full raw standardized feature vector (AlertDetailOut.features) -- collapsed
 * by default. Useful for a technical/demo audience, but 76 values is too much to
 * show prominently on an investigation screen an analyst actually has to scan.
 */
export function RawFeaturesSection({ features }: { features: FeatureVector }) {
  const entries = Object.entries(features).sort(([a], [b]) => a.localeCompare(b));

  return (
    <details className="raw-features">
      <summary>Show raw model features ({entries.length})</summary>
      <div className="raw-features-grid">
        {entries.map(([name, value]) => (
          <div key={name} className="raw-features-row">
            <span className="raw-features-name">{name}</span>
            <span className="raw-features-value">{formatFeatureValue(value)}</span>
          </div>
        ))}
      </div>
    </details>
  );
}
