import type { CSSProperties } from "react";
import type { StatsSummaryOut } from "../../types/api";
import "./SecurityPosture.css";

type Tone = "high" | "medium" | "low" | "none";

function posture(summary: StatsSummaryOut): { label: string; tone: Tone; detail: string } {
  const total = summary.total_alerts;
  const high = summary.risk_level_counts.High ?? 0;
  const medium = summary.risk_level_counts.Medium ?? 0;

  if (total === 0) {
    return { label: "No alerts yet", tone: "none", detail: "Waiting on the first scored window." };
  }
  if (high > 0) {
    return {
      label: "Active threats",
      tone: "high",
      detail: `${high} High-risk alert${high === 1 ? "" : "s"} currently on record.`,
    };
  }
  if (medium > 0) {
    return {
      label: "Elevated activity",
      tone: "medium",
      detail: `${medium} Medium-risk alert${medium === 1 ? "" : "s"}, no High-risk activity.`,
    };
  }
  return { label: "Normal", tone: "low", detail: `All ${total.toLocaleString()} recorded alerts are Low risk.` };
}

/**
 * A single, compact "is my network safe right now" read -- built entirely from
 * GET /api/stats/summary (the same data the stat tiles below already show), using a
 * CSS conic-gradient ring rather than a charting dependency. The posture label/detail
 * are derived directly from these same counts, not a separately fabricated metric.
 */
export function SecurityPosture({ summary }: { summary: StatsSummaryOut }) {
  const total = summary.total_alerts;
  const high = summary.risk_level_counts.High ?? 0;
  const medium = summary.risk_level_counts.Medium ?? 0;
  const low = summary.risk_level_counts.Low ?? 0;
  const { label, tone, detail } = posture(summary);

  const highPct = total > 0 ? (high / total) * 100 : 0;
  const medPct = total > 0 ? (medium / total) * 100 : 0;
  const ringStyle: CSSProperties =
    total > 0
      ? {
          background: `conic-gradient(var(--risk-high) 0% ${highPct}%, var(--risk-med) ${highPct}% ${highPct + medPct}%, var(--risk-low) ${highPct + medPct}% 100%)`,
        }
      : { background: "var(--bg-panel-raised-2)" };

  // The ring's center number is whichever count is most operationally relevant right
  // now: High-risk if any exist (the thing an analyst needs to see first), otherwise
  // the total alert count (there's nothing urgent to single out).
  const centerValue = high > 0 ? high : total;
  const centerCaption = high > 0 ? "High risk" : "total alerts";

  return (
    <div className="security-posture">
      <div className="posture-ring" style={ringStyle} role="img" aria-label={`Security posture: ${label}. ${detail}`}>
        <div className="posture-ring-hole">
          <span className={`posture-ring-value posture-ring-value--${tone}`}>{centerValue}</span>
          <span className="posture-ring-caption">{centerCaption}</span>
        </div>
      </div>

      <div className="posture-summary">
        <div className={`posture-label posture-label--${tone}`}>{label}</div>
        <p className="posture-detail">{detail}</p>
        <div className="posture-breakdown">
          <span className="posture-chip posture-chip--high">
            <i />High <b>{high}</b>
          </span>
          <span className="posture-chip posture-chip--medium">
            <i />Medium <b>{medium}</b>
          </span>
          <span className="posture-chip posture-chip--low">
            <i />Low <b>{low}</b>
          </span>
        </div>
      </div>
    </div>
  );
}
