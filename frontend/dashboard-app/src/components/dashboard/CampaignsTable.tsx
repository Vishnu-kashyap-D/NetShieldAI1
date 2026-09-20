import type { CampaignOut } from "../../types/api";
import { ThreatLabel } from "../common/ThreatLabel";
import { formatFullDateTime, formatPercent } from "../../utils/format";
import "./RecentAlertsTable.css";

/**
 * Sustained activity found by the cross-window layer: a run of consecutive windows the classifier kept reading as
 * one category at very high confidence, most of which raised NO alert on their own. Reads "27 windows, 0 alerting
 * alone" for the classic slow attack -- exactly the case per-window alerting cannot see.
 */
export function CampaignsTable({ campaigns }: { campaigns: CampaignOut[] }) {
  return (
    <div className="recent-alerts-wrap">
      <table className="recent-alerts-table">
        <thead>
          <tr>
            <th>Detected</th>
            <th>Source</th>
            <th>Rows</th>
            <th>Category</th>
            <th>Windows</th>
            <th>Alerting alone</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody>
          {campaigns.map((c) => (
            <tr key={c.id}>
              <td className="mono">{formatFullDateTime(c.detected_at)}</td>
              <td className="mono" title={c.source_file}>{c.source_file}</td>
              <td className="mono">
                {c.first_window.toLocaleString()}–{c.last_window.toLocaleString()}
              </td>
              <td>
                <ThreatLabel label={c.category} />
              </td>
              <td className="mono">{c.windows}</td>
              <td className="mono" title="Windows in this run that raised a Medium/High alert on their own. The rest were only visible in aggregate.">
                {c.alerted_windows} of {c.windows}
              </td>
              <td className="mono">{formatPercent(c.mean_confidence)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
