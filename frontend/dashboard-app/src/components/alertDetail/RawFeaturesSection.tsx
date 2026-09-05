import type { FeatureVector } from "../../types/api";
import { FEATURE_GLOSSARY } from "../../data/featureGlossary";
import { IconInfo } from "../common/icons";
import "./RawFeaturesSection.css";

function formatFeatureValue(value: number | null): string {
  if (value === null) return "—";
  return Number.isInteger(value) ? String(value) : value.toFixed(4);
}

/**
 * The full raw standardized feature vector (AlertDetailOut.features) -- collapsed
 * by default. Useful for a technical/demo audience, but 76 values is too much to
 * show prominently on an investigation screen an analyst actually has to scan.
 * Feature names get a definition tooltip from the existing glossary where one
 * exists -- never an invented definition for a name the glossary doesn't have.
 */
export function RawFeaturesSection({ features }: { features: FeatureVector }) {
  const entries = Object.entries(features).sort(([a], [b]) => a.localeCompare(b));

  return (
    <details className="raw-features">
      <summary>Show raw model features ({entries.length})</summary>
      <div className="raw-features-grid">
        {entries.map(([name, value]) => {
          const definition = FEATURE_GLOSSARY[name];
          return (
            <div key={name} className="raw-features-row">
              <span className="raw-features-name">
                {name}
                {definition && (
                  <span className="raw-features-info" tabIndex={0} title={definition} aria-label={`${name}: ${definition}`}>
                    <IconInfo />
                  </span>
                )}
              </span>
              <span className="raw-features-value">{formatFeatureValue(value)}</span>
            </div>
          );
        })}
      </div>
    </details>
  );
}
