import type { RiskLevel } from "../../types/api";

const RISK_CLASS: Record<RiskLevel, string> = {
  Low: "risk-low",
  Medium: "risk-medium",
  High: "risk-high",
};

/** Consistent Low/Medium/High visual treatment, used everywhere a risk_level is shown. */
export function RiskBadge({ level }: { level: RiskLevel }) {
  return <span className={`badge ${RISK_CLASS[level]}`}>{level}</span>;
}
