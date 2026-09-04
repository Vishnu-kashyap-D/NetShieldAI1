import type { ShapDirection, ShapFeature } from "../../types/api";
import { IconInfo } from "../common/icons";
import "./ShapDivergingBars.css";

interface ShapDivergingBarsProps {
  /** Already sorted by mean_abs_shap descending -- ranking is unchanged from before. */
  features: ShapFeature[];
  /** Exact technical caption for a positive value, e.g. "Increased predicted-class output". */
  positiveCaption: string;
  /** Exact technical caption for a negative value, e.g. "Decreased predicted-class output". */
  negativeCaption: string;
  /** Plain-language definitions from the existing feature glossary -- never invented here. */
  glossary: Record<string, string>;
}

function formatSigned(value: number | undefined): string {
  if (value === undefined) return "sign n/a";
  return `${value >= 0 ? "+" : ""}${value.toFixed(4)}`;
}

/**
 * A signed/diverging bar per feature -- positive bars extend right of a centerline,
 * negative bars extend left, both sized by magnitude (mean_abs_shap). Direction is
 * never conveyed by color alone: every row also prints the signed value as text and
 * an explicit direction word is available via the axis captions above. A feature
 * whose direction is "unknown" (an alert scored before signed SHAP existed) renders
 * as a flat dot at the centerline, never a guessed bar.
 */
export function ShapDivergingBars({ features, positiveCaption, negativeCaption, glossary }: ShapDivergingBarsProps) {
  const maxAbs = Math.max(1e-9, ...features.map((f) => f.mean_abs_shap));

  return (
    <div className="shap-diverging">
      <div className="shap-diverging-axis">
        <span>&larr; {negativeCaption}</span>
        <span className="shap-diverging-axis-pos">{positiveCaption} &rarr;</span>
      </div>
      <div className="shap-diverging-rows">
        {features.map((entry) => {
          const direction: ShapDirection = entry.direction ?? "unknown";
          const barWidthPct = (entry.mean_abs_shap / maxAbs) * 50;
          const definition = glossary[entry.feature];

          return (
            <div className="shap-diverging-row" key={entry.feature}>
              <span className="shap-diverging-label">
                <span className="shap-diverging-label-text" title={entry.feature}>
                  {entry.feature}
                </span>
                {definition && (
                  <span className="shap-diverging-info" tabIndex={0} title={definition} aria-label={`${entry.feature}: ${definition}`}>
                    <IconInfo />
                  </span>
                )}
              </span>

              <div className="shap-diverging-track">
                <div className="shap-diverging-center" />
                {direction === "positive" && (
                  <div className="shap-diverging-bar shap-diverging-bar--pos" style={{ width: `${barWidthPct}%` }} />
                )}
                {direction === "negative" && (
                  <div className="shap-diverging-bar shap-diverging-bar--neg" style={{ width: `${barWidthPct}%` }} />
                )}
                {(direction === "neutral" || direction === "unknown") && (
                  <div
                    className="shap-diverging-dot"
                    title={direction === "unknown" ? "Sign not available for this alert" : "No net direction"}
                  />
                )}
              </div>

              <span className={`shap-diverging-value shap-diverging-value--${direction}`}>
                {formatSigned(entry.shap_value)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
