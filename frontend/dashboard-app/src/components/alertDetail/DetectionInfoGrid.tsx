import type { ReactNode } from "react";
import "./DetectionInfoGrid.css";

export interface DetectionInfoItem {
  key: string;
  label: string;
  value: ReactNode | null | undefined;
}

const NOT_AVAILABLE = <span className="detection-info-na">Not available</span>;

/** A label/value grid for the alert's metadata fields -- shows "Not available" instead of breaking on a null/empty value. */
export function DetectionInfoGrid({ items }: { items: DetectionInfoItem[] }) {
  return (
    <div className="detection-info-grid">
      {items.map((item) => (
        <div className="detection-info-cell" key={item.key}>
          <div className="detection-info-label">{item.label}</div>
          <div className="detection-info-value">
            {item.value === null || item.value === undefined || item.value === "" ? NOT_AVAILABLE : item.value}
          </div>
        </div>
      ))}
    </div>
  );
}
