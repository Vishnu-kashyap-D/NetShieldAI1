import type { StatsSummaryOut } from "../../types/api";
import "./RiskLevelBreakdown.css";

/**
 * A proportional (percentage-of-total) view of the same risk_level_counts the stat
 * tiles show as raw counts -- a different, genuinely useful read (relative share)
 * rather than a restatement of the same numbers in the same form.
 */
export function RiskLevelBreakdown({ summary }: { summary: StatsSummaryOut }) {
  const total = summary.total_alerts;
  const high = summary.risk_level_counts.High ?? 0;
  const medium = summary.risk_level_counts.Medium ?? 0;
  const low = summary.risk_level_counts.Low ?? 0;

  if (total === 0) {
    return (
      <div className="empty-state">
        <div className="glyph">&#9676;</div>
        No alerts scored yet.
      </div>
    );
  }

  const pct = (n: number) => (n / total) * 100;

  return (
    <div className="risk-breakdown">
      {/* Decorative -- the legend below states the same percentages and counts as text. */}
      <div className="risk-breakdown-bar" aria-hidden="true">
        {high > 0 && <div className="risk-breakdown-seg risk-breakdown-seg--high" style={{ width: `${pct(high)}%` }} />}
        {medium > 0 && (
          <div className="risk-breakdown-seg risk-breakdown-seg--medium" style={{ width: `${pct(medium)}%` }} />
        )}
        {low > 0 && <div className="risk-breakdown-seg risk-breakdown-seg--low" style={{ width: `${pct(low)}%` }} />}
      </div>
      <div className="risk-breakdown-legend">
        <div className="risk-breakdown-row">
          <span className="risk-breakdown-dot risk-breakdown-dot--high" />
          <span className="risk-breakdown-label">High</span>
          <span className="risk-breakdown-pct">{pct(high).toFixed(1)}%</span>
          <span className="risk-breakdown-count">{high.toLocaleString()}</span>
        </div>
        <div className="risk-breakdown-row">
          <span className="risk-breakdown-dot risk-breakdown-dot--medium" />
          <span className="risk-breakdown-label">Medium</span>
          <span className="risk-breakdown-pct">{pct(medium).toFixed(1)}%</span>
          <span className="risk-breakdown-count">{medium.toLocaleString()}</span>
        </div>
        <div className="risk-breakdown-row">
          <span className="risk-breakdown-dot risk-breakdown-dot--low" />
          <span className="risk-breakdown-label">Low</span>
          <span className="risk-breakdown-pct">{pct(low).toFixed(1)}%</span>
          <span className="risk-breakdown-count">{low.toLocaleString()}</span>
        </div>
      </div>
    </div>
  );
}
