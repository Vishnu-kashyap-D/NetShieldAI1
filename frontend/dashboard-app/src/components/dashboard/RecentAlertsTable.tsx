import { useNavigate } from "react-router-dom";
import type { AlertOut } from "../../types/api";
import { RiskBadge } from "../common/RiskBadge";
import { formatClockTime, formatPercent, formatRelativeTime } from "../../utils/format";
import "./RecentAlertsTable.css";

export function RecentAlertsTable({ alerts, now }: { alerts: AlertOut[]; now: number }) {
  const navigate = useNavigate();

  return (
    <div className="recent-alerts-wrap">
      <table className="recent-alerts-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Category</th>
            <th>Risk</th>
            <th>Confidence</th>
            <th>Risk score</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} onClick={() => navigate(`/alerts/${alert.id}`)} tabIndex={0}>
              <td className="mono" title={new Date(alert.ingested_at).toLocaleString()}>
                {formatClockTime(alert.ingested_at)}
                <span className="recent-alerts-relative">{formatRelativeTime(alert.ingested_at, now)}</span>
              </td>
              <td>{alert.predicted_label}</td>
              <td>
                <RiskBadge level={alert.risk_level} />
              </td>
              <td className="mono">{alert.is_anomaly ? formatPercent(alert.confidence) : "--"}</td>
              <td className="mono">{alert.risk_score.toFixed(3)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
