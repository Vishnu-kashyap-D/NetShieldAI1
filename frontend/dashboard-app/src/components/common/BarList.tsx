import type { ReactNode } from "react";
import "./BarList.css";

export interface BarListItem {
  key: string;
  label: string;
  /** Raw magnitude used to size the bar -- must be >= 0 (this is a magnitude/sequential display, never signed). */
  value: number;
  /** Pre-formatted string shown at the end of the row. */
  displayValue: string;
  /**
   * Optional small element rendered before the label (e.g. a signed-direction chip). The bar
   * itself stays unsigned/single-hue either way -- this only annotates the label, it never
   * changes what `value` sizes the bar to.
   */
  labelPrefix?: ReactNode;
}

interface BarListProps {
  items: BarListItem[];
  /** CSS width for the label column, e.g. "118px" or "auto" (grows with content). Default "auto". */
  labelWidth?: string;
  /** Which theme accent the fill uses. Both are a single hue (magnitude, not identity/comparison between rows of different color). */
  accent?: "brand" | "teal";
}

/**
 * A horizontal magnitude bar list: one hue, longer bar = larger value. Used for
 * both the category-distribution chart and SHAP feature-importance panels --
 * both are "how much", never "which of several signed directions", so a single
 * accent color per list is the correct, honest treatment (see dataviz guidance:
 * sequential/magnitude data gets one hue, not a categorical palette).
 */
export function BarList({ items, labelWidth = "auto", accent = "brand" }: BarListProps) {
  const maxValue = Math.max(1e-9, ...items.map((item) => item.value));

  return (
    <div className="bar-list">
      {items.map((item) => (
        <div className="bar-list-row" style={{ gridTemplateColumns: `${labelWidth} 1fr auto` }} key={item.key}>
          <span className="bar-list-label" title={item.label}>
            {item.labelPrefix}
            {item.label}
          </span>
          <div className="bar-list-track">
            <div
              className={`bar-list-fill bar-list-fill--${accent}`}
              style={{ width: `${(item.value / maxValue) * 100}%` }}
            />
          </div>
          <span className="bar-list-value">{item.displayValue}</span>
        </div>
      ))}
    </div>
  );
}
