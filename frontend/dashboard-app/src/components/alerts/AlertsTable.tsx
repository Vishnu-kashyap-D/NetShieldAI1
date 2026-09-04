import { useNavigate } from "react-router-dom";
import type { AlertOut } from "../../types/api";
import { RiskBadge } from "../common/RiskBadge";
import { formatPercent } from "../../utils/format";
import "./AlertsTable.css";

function formatFullTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "--";
  return date.toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function AlertsTable({ alerts }: { alerts: AlertOut[] }) {
  const navigate = useNavigate();

  return (
    <div className="alerts-table-wrap">
      <table className="alerts-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Threat</th>
            <th>Risk</th>
            <th>Confidence</th>
            <th>Anomaly</th>
            <th>Risk score</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr
              key={alert.id}
              tabIndex={0}
              onClick={() => navigate(`/alerts/${alert.id}`)}
              onKeyDown={(e) => {
                if (e.key === "Enter") navigate(`/alerts/${alert.id}`);
              }}
            >
              <td data-label="Time" className="mono" title={new Date(alert.ingested_at).toLocaleString()}>
                {formatFullTimestamp(alert.ingested_at)}
              </td>
              <td data-label="Threat">{alert.predicted_label}</td>
              <td data-label="Risk">
                <RiskBadge level={alert.risk_level} />
              </td>
              <td data-label="Confidence" className="mono">
                {alert.is_anomaly ? formatPercent(alert.confidence) : "--"}
              </td>
              <td data-label="Anomaly" className="mono">
                {alert.anomaly_score.toFixed(2)}
              </td>
              <td data-label="Risk score" className="mono">
                {alert.risk_score.toFixed(2)}
              </td>
              <td data-label="Source" className="source-cell" title={alert.source_file}>
                {alert.source_file}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
