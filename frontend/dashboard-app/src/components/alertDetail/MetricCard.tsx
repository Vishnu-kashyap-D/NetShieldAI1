import type { ReactNode } from "react";
import "./MetricCard.css";

interface MetricCardProps {
  label: string;
  value: ReactNode;
  /** A short, factual description of what this metric is -- not an interpretation of what it "means" for this specific alert. */
  help: string;
}

/** One analyst-readable detection metric, with a short explanation of what it represents. */
export function MetricCard({ label, value, help }: MetricCardProps) {
  return (
    <div className="metric-card">
      <div className="metric-card-label">{label}</div>
      <div className="metric-card-value">{value}</div>
      <div className="metric-card-help">{help}</div>
    </div>
  );
}
