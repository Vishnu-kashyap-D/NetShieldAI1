import type { DriftOut, DriftStatus } from "../../types/api";
import { formatPercent } from "../../utils/format";
import "./DriftCard.css";

const STATUS_LABEL: Record<DriftStatus, string> = {
  stable: "Stable",
  watch: "Watch",
  drifting: "Drifting",
  insufficient_data: "Not enough data",
  unavailable: "Unavailable",
};

const STATUS_CLASS: Record<DriftStatus, string> = {
  stable: "risk-low",
  watch: "risk-medium",
  drifting: "risk-high",
  insufficient_data: "drift-neutral",
  unavailable: "drift-neutral",
};

/**
 * Concept drift at a glance: is ordinary (unflagged) traffic still scoring like the validation traffic the
 * risk thresholds were calibrated on? The bars compare the share of live windows in each score band with the
 * share validation had (10% per band by construction); a shape that leans one way is the drift.
 */
export function DriftCard({ drift }: { drift: DriftOut }) {
  const hasChart = drift.bins.length > 0;

  return (
    <div className="drift-card">
      <div className="drift-head">
        <span className={`badge ${STATUS_CLASS[drift.status]}`}>{STATUS_LABEL[drift.status]}</span>
        {drift.psi !== null && (
          <span className="drift-psi" title={`Population Stability Index. Below ${drift.psi_watch} stable, ${drift.psi_watch}-${drift.psi_drifting} watch, above ${drift.psi_drifting} drifting.`}>
            PSI <b>{drift.psi.toFixed(3)}</b>
          </span>
        )}
        <span className="drift-period">last {drift.period_hours} h</span>
      </div>

      <p className="drift-message">{drift.message}</p>

      {hasChart && (
        <div className="drift-chart" role="img" aria-label="Share of live windows per score band compared with validation">
          {drift.bins.map((bin) => (
            <div className="drift-col" key={bin.bin} title={`Band ${bin.bin + 1}: live ${formatPercent(bin.live)} vs validation ${formatPercent(bin.expected)}`}>
              <div className="drift-bars">
                <div className="drift-bar drift-bar--expected" style={{ height: `${Math.min(100, bin.expected * 300)}%` }} />
                <div className="drift-bar drift-bar--live" style={{ height: `${Math.min(100, bin.live * 300)}%` }} />
              </div>
              <span className="drift-bin-label">{bin.bin + 1}</span>
            </div>
          ))}
        </div>
      )}
      {hasChart && (
        <div className="drift-legend">
          <span><i className="drift-swatch drift-swatch--expected" /> validation</span>
          <span><i className="drift-swatch drift-swatch--live" /> live</span>
          <span className="drift-axis-note">score band: 1 = lowest reconstruction error, {drift.bins.length} = just under the anomaly threshold</span>
        </div>
      )}

      <div className="drift-facts">
        <span>
          {drift.windows.toLocaleString()} windows scored ({drift.quiet_windows.toLocaleString()} unflagged) across{" "}
          {drift.batches_considered} ingest{drift.batches_considered === 1 ? "" : "s"}
        </span>
        {drift.flag_rate !== null && drift.reference_flag_rate !== null && (
          <span title="Real attacks raise this legitimately, so it is context, not part of the drift verdict.">
            Alert rate {formatPercent(drift.flag_rate)} vs {formatPercent(drift.reference_flag_rate)} false-alarm rate in validation
            {drift.flag_rate_ratio !== null ? ` (${drift.flag_rate_ratio.toFixed(1)}×)` : ""}
          </span>
        )}
        {drift.batches_excluded > 0 && (
          <span>
            {drift.batches_excluded} earlier ingest{drift.batches_excluded === 1 ? "" : "s"} scored under a previous model left out
          </span>
        )}
      </div>
    </div>
  );
}
