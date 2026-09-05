import { useEffect, useRef, useState } from "react";
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

interface AlertsTableProps {
  alerts: AlertOut[];
  /** Only the "latest, unfiltered, page 1" view flashes newly-arrived rows on a poll --
      elsewhere an id changing between renders usually just means the analyst changed
      a filter or page, not that something new actually arrived. */
  enableLiveFlash?: boolean;
}

export function AlertsTable({ alerts, enableLiveFlash = false }: AlertsTableProps) {
  const navigate = useNavigate();

  const previousIdsRef = useRef<Set<number> | null>(null);
  const [newlyArrivedIds, setNewlyArrivedIds] = useState<Set<number>>(new Set());

  useEffect(() => {
    if (!enableLiveFlash) {
      previousIdsRef.current = null;
      return;
    }
    const currentIds = new Set(alerts.map((a) => a.id));
    const previousIds = previousIdsRef.current;
    previousIdsRef.current = currentIds;
    if (!previousIds) return;

    const arrived = [...currentIds].filter((id) => !previousIds.has(id));
    if (arrived.length === 0) return;
    setNewlyArrivedIds(new Set(arrived));
    const timer = setTimeout(() => setNewlyArrivedIds(new Set()), 2400);
    return () => clearTimeout(timer);
  }, [alerts, enableLiveFlash]);

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
              className={`severity-row severity-row--${alert.risk_level.toLowerCase()}${newlyArrivedIds.has(alert.id) ? " row-flash" : ""}`}
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
