import { Link } from "react-router-dom";
import type { AlertListOut, StatsSummaryOut } from "../../types/api";
import { useDataProvider } from "../../data/DataModeContext";
import { usePolledAsync } from "../../hooks/usePolledAsync";
import { PageHeader } from "../../components/common/PageHeader";
import { SectionCard } from "../../components/common/SectionCard";
import { AsyncSection } from "../../components/common/AsyncSection";
import { StatTile, IconAlerts, IconWarningTriangle, IconCheckCircle } from "../../components/dashboard/StatTile";
import { RiskTimeseriesChart } from "../../components/dashboard/RiskTimeseriesChart";
import { CategoryDistribution } from "../../components/dashboard/CategoryDistribution";
import { RiskLevelBreakdown } from "../../components/dashboard/RiskLevelBreakdown";
import { MetricCard } from "../../components/alertDetail/MetricCard";
import { TrainingStatusBadge } from "../../components/retraining/TrainingStatusBadge";
import { formatPercent } from "../../utils/format";
import "./AnalyticsPage.css";

const POLL_MS = 20_000;
// A longer window than the Dashboard's own trend chart (150 min) -- this page is
// specifically for a deeper look, not a restatement of the Dashboard's live view.
const TREND_PARAMS = { minutes: 1440, bucket_seconds: 1800 };
// The largest page the real API allows (backend/app/routers/alerts.py caps limit at
// 500) -- "detection metrics" below are honestly labeled as derived from this sample,
// never claimed as a true all-time average unless the sample happens to cover everything.
const SAMPLE_LIMIT = 500;

/**
 * Averages actually computed from real per-alert fields already returned by
 * GET /api/alerts -- never a fabricated percentage or trend. `avgConfidence` is
 * null (not 0) when no fetched alert reached the classifier, so the UI can say
 * "not enough data" instead of showing a misleading 0%.
 */
function computeDetectionMetrics(list: AlertListOut) {
  const classified = list.items.filter((a) => a.is_anomaly);
  const avgConfidence =
    classified.length > 0 ? classified.reduce((sum, a) => sum + a.confidence, 0) / classified.length : null;
  const avgAnomalyScore =
    list.items.length > 0 ? list.items.reduce((sum, a) => sum + a.anomaly_score, 0) / list.items.length : null;
  const threshold = list.items[0]?.anomaly_threshold ?? null;
  return { avgConfidence, avgAnomalyScore, threshold, classifiedCount: classified.length, sampledCount: list.items.length };
}

function anomalyGateRate(summary: StatsSummaryOut): number | null {
  return summary.total_alerts > 0 ? summary.anomaly_count / summary.total_alerts : null;
}

export function AnalyticsPage() {
  const provider = useDataProvider();
  const stats = usePolledAsync(() => provider.getStatsSummary(), [provider], POLL_MS);
  const trend = usePolledAsync(() => provider.getTimeseries(TREND_PARAMS), [provider], POLL_MS);
  const sample = usePolledAsync(() => provider.listAlerts({ limit: SAMPLE_LIMIT, offset: 0 }), [provider], POLL_MS);
  const feedback = usePolledAsync(() => provider.listFeedback(), [provider], POLL_MS);
  const retrainRuns = usePolledAsync(() => provider.listRetrainRuns(), [provider], POLL_MS);

  const dataSourceNotice = provider.getDataSourceNotice();
  const latestRun = retrainRuns.data
    ? [...retrainRuns.data].sort((a, b) => b.started_at.localeCompare(a.started_at))[0]
    : undefined;

  return (
    <section>
      <PageHeader title="Analytics" subtitle="Aggregate trends across every alert this data source has scored" />

      {dataSourceNotice && <div className="data-source-notice">{dataSourceNotice}</div>}

      <AsyncSection {...stats} emptyLabel="No alerts scored yet." loadingLabel="Loading summary…">
        {(summary) => (
          <div className="stat-row">
            <StatTile
              icon={<IconAlerts />}
              tone="blue"
              value={summary.total_alerts.toLocaleString()}
              label="Total alerts"
              badge="All time"
            />
            <StatTile
              icon={<IconWarningTriangle />}
              tone="red"
              value={(summary.risk_level_counts.High ?? 0).toLocaleString()}
              label="High-risk alerts"
            />
            <StatTile
              icon={<IconWarningTriangle />}
              tone="orange"
              value={(summary.risk_level_counts.Medium ?? 0).toLocaleString()}
              label="Medium-risk alerts"
            />
            <StatTile
              icon={<IconCheckCircle />}
              tone="green"
              value={(summary.risk_level_counts.Low ?? 0).toLocaleString()}
              label="Low-risk alerts"
            />
          </div>
        )}
      </AsyncSection>

      <SectionCard title="Risk activity — last 24 hours" subtitle="Alerts bucketed over a longer window, split by risk level">
        <AsyncSection
          {...trend}
          isEmpty={(points) => points.length === 0}
          emptyLabel="No alert activity in the last 24 hours."
          loadingLabel="Loading activity…"
        >
          {(points) => (
            <>
              <RiskTimeseriesChart points={points} />
              <div className="chart-legend">
                <span>
                  <i style={{ background: "var(--risk-low)" }} />
                  Low
                </span>
                <span>
                  <i style={{ background: "var(--risk-med)" }} />
                  Medium
                </span>
                <span>
                  <i style={{ background: "var(--risk-high)" }} />
                  High
                </span>
              </div>
            </>
          )}
        </AsyncSection>
      </SectionCard>

      <div className="grid-2">
        <SectionCard title="Threat category distribution" subtitle="Predicted category across every stored alert">
          <AsyncSection {...stats} emptyLabel="No category data yet." loadingLabel="Loading categories…">
            {(summary) => <CategoryDistribution counts={summary.category_counts} />}
          </AsyncSection>
        </SectionCard>

        <SectionCard title="Risk-level breakdown" subtitle="Share of all alerts at each risk level">
          <AsyncSection {...stats} emptyLabel="No alerts scored yet." loadingLabel="Loading breakdown…">
            {(summary) => <RiskLevelBreakdown summary={summary} />}
          </AsyncSection>
        </SectionCard>
      </div>

      <SectionCard
        title="Model & detection metrics"
        subtitle="Derived from the most recently scored alerts -- not a separate backend statistic"
      >
        {stats.data && sample.data ? (
          <DetectionMetricsGrid summary={stats.data} sample={sample.data} />
        ) : stats.status === "error" || sample.status === "error" ? (
          <div className="error-state" role="alert">
            Couldn't load detection metrics.
          </div>
        ) : (
          <div className="empty-state" role="status" aria-live="polite">
            <div className="skeleton" style={{ height: 14, width: "40%", margin: "0 auto" }} />
          </div>
        )}
      </SectionCard>

      <SectionCard title="Feedback &amp; retraining" subtitle="Analyst validation activity and the model's training history">
        <div className="analytics-fr-row">
          <div className="analytics-fr-metric">
            <div className="label-eyebrow">Feedback submitted</div>
            <div className="hero-metric analytics-fr-value">
              {feedback.data ? feedback.data.length.toLocaleString() : feedback.status === "error" ? "—" : "…"}
            </div>
            <div className="analytics-fr-help">Analyst-validated corrections recorded across all alerts.</div>
            <Link to="/feedback" className="analytics-fr-link">
              View feedback log →
            </Link>
          </div>
          <div className="analytics-fr-divider" />
          <div className="analytics-fr-metric">
            <div className="label-eyebrow">Latest retraining run</div>
            <div className="analytics-fr-value">
              {latestRun ? (
                <TrainingStatusBadge status={latestRun.status} />
              ) : retrainRuns.status === "error" ? (
                "—"
              ) : retrainRuns.status === "loading" && !retrainRuns.hasLoadedOnce ? (
                "…"
              ) : (
                <span className="analytics-fr-none">No runs yet</span>
              )}
            </div>
            <div className="analytics-fr-help">
              {latestRun
                ? `Run #${latestRun.id} · ${latestRun.feedback_rows_used ?? 0} feedback rows used`
                : "Triggered from accumulated analyst feedback."}
            </div>
            <Link to="/retraining" className="analytics-fr-link">
              View retraining →
            </Link>
          </div>
        </div>
      </SectionCard>
    </section>
  );
}

function DetectionMetricsGrid({ summary, sample }: { summary: StatsSummaryOut; sample: AlertListOut }) {
  const gateRate = anomalyGateRate(summary);
  const { avgConfidence, avgAnomalyScore, threshold, classifiedCount, sampledCount } = computeDetectionMetrics(sample);
  const sampleNote =
    sample.total > sampledCount
      ? `Based on the most recent ${sampledCount.toLocaleString()} of ${sample.total.toLocaleString()} scored alerts.`
      : `Based on all ${sampledCount.toLocaleString()} scored alerts.`;

  return (
    <div className="metric-grid">
      <MetricCard
        label="Anomaly gate rate"
        value={gateRate !== null ? formatPercent(gateRate) : "N/A"}
        help="Share of all scored windows the Autoencoder's anomaly gate flagged for classification."
      />
      <MetricCard
        label="Avg. classifier confidence"
        value={avgConfidence !== null ? formatPercent(avgConfidence) : "Not enough classified alerts yet"}
        help={
          avgConfidence !== null
            ? `Averaged across the ${classifiedCount.toLocaleString()} classified alerts in this sample. ${sampleNote}`
            : "No alert in this sample reached the classifier."
        }
      />
      <MetricCard
        label="Avg. anomaly score"
        value={avgAnomalyScore !== null ? avgAnomalyScore.toFixed(4) : "N/A"}
        help={
          avgAnomalyScore !== null
            ? `${sampleNote}${threshold !== null ? ` Calibrated threshold: ${threshold.toFixed(4)}.` : ""}`
            : "No alerts in this sample."
        }
      />
    </div>
  );
}
