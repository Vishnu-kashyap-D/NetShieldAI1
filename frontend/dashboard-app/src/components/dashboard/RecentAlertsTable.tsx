import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { AlertOut } from "../../types/api";
import { RiskBadge } from "../common/RiskBadge";
import { formatClockTime, formatPercent, formatRelativeTime } from "../../utils/format";
import "./RecentAlertsTable.css";

export function RecentAlertsTable({ alerts, now }: { alerts: AlertOut[]; now: number }) {
  const navigate = useNavigate();

  // A brief flash on rows whose id wasn't present the previous time this list was
  // fetched -- real id-diffing across polls, not a fabricated "new" flag from the API.
  const previousIdsRef = useRef<Set<number> | null>(null);
  const [newlyArrivedIds, setNewlyArrivedIds] = useState<Set<number>>(new Set());

  useEffect(() => {
    const currentIds = new Set(alerts.map((a) => a.id));
    const previousIds = previousIdsRef.current;
    previousIdsRef.current = currentIds;
    if (!previousIds) return; // first load -- nothing has "just arrived" yet

    const arrived = [...currentIds].filter((id) => !previousIds.has(id));
    if (arrived.length === 0) return;
    setNewlyArrivedIds(new Set(arrived));
    const timer = setTimeout(() => setNewlyArrivedIds(new Set()), 2400);
    return () => clearTimeout(timer);
  }, [alerts]);

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
            <tr
              key={alert.id}
              className={`severity-row severity-row--${alert.risk_level.toLowerCase()}${newlyArrivedIds.has(alert.id) ? " row-flash" : ""}`}
              onClick={() => navigate(`/alerts/${alert.id}`)}
              tabIndex={0}
            >
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
