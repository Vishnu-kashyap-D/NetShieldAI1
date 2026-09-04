import { useEffect, useRef, useState } from "react";
import { useDataProvider } from "../../data/DataModeContext";
import type { SimulatedWorkflowEvent } from "../../data/mock/scenario";
import { usePolledAsync } from "../../hooks/usePolledAsync";
import { PageHeader } from "../../components/common/PageHeader";
import { SectionCard } from "../../components/common/SectionCard";
import { AsyncSection } from "../../components/common/AsyncSection";
import { StatTile, IconAlerts, IconWarningTriangle, IconCheckCircle } from "../../components/dashboard/StatTile";
import { RiskTimeseriesChart } from "../../components/dashboard/RiskTimeseriesChart";
import { CategoryDistribution } from "../../components/dashboard/CategoryDistribution";
import { RecentAlertsTable } from "../../components/dashboard/RecentAlertsTable";
import { HealthBanner } from "../../components/dashboard/HealthBanner";
import { DemoScenarioPanel } from "../../components/dashboard/DemoScenarioPanel";
import "./Dashboard.css";

const POLL_MS = 12_000;
const TIMESERIES_PARAMS = { minutes: 150, bucket_seconds: 180 };

export function Dashboard() {
  const provider = useDataProvider();
  const [now, setNow] = useState(() => Date.now());

  const health = usePolledAsync(() => provider.getHealth(), [provider], 15_000);
  const stats = usePolledAsync(() => provider.getStatsSummary(), [provider], POLL_MS);
  const timeseries = usePolledAsync(() => provider.getTimeseries(TIMESERIES_PARAMS), [provider], POLL_MS);
  const recentAlerts = usePolledAsync(() => provider.listAlerts({ limit: 8 }), [provider], POLL_MS);

  // Tick "time ago" labels on recent alerts without waiting for the next poll.
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const refreshAll = useRef<() => void>(() => {});
  useEffect(() => {
    refreshAll.current = () => {
      stats.refresh();
      timeseries.refresh();
      recentAlerts.refresh();
    };
  });

  // The Demo Scenario panel (mock mode only) drives the mock provider's own
  // simulateLiveIncident() when the presenter clicks "Run Demo Scenario" -- this
  // just refreshes the dashboard's own data whenever that scenario creates a new
  // alert, the same way any other listAlerts/getStatsSummary/getTimeseries change
  // would. Nothing here bypasses the DataProvider or runs a second simulation.
  function handleWorkflowEvent(event: SimulatedWorkflowEvent) {
    if (event.type === "alert_created") refreshAll.current();
  }

  const dataSourceNotice = provider.getDataSourceNotice();

  return (
    <section>
      <PageHeader title="Security Overview" subtitle="Real-time network monitoring and hybrid threat detection" />

      {dataSourceNotice && <div className="data-source-notice">{dataSourceNotice}</div>}

      {health.data && <HealthBanner health={health.data} />}

      <DemoScenarioPanel onWorkflowEvent={handleWorkflowEvent} />

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

      <div className="grid-2">
        <SectionCard title="Alert activity over time" subtitle="Alerts bucketed over time, split by risk level">
          <AsyncSection
            {...timeseries}
            isEmpty={(points) => points.length === 0}
            emptyLabel="No alert activity in this time window yet."
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

        <SectionCard title="By category" subtitle="Predicted category across stored alerts">
          <AsyncSection {...stats} emptyLabel="No category data yet." loadingLabel="Loading categories…">
            {(summary) => <CategoryDistribution counts={summary.category_counts} />}
          </AsyncSection>
        </SectionCard>
      </div>

      <SectionCard title="Recent alerts" subtitle="Latest 8 — the Alerts page has full history and filters">
        <AsyncSection
          {...recentAlerts}
          isEmpty={(list) => list.items.length === 0}
          emptyLabel="No alerts recorded yet."
          loadingLabel="Loading recent alerts…"
        >
          {(list) => <RecentAlertsTable alerts={list.items} now={now} />}
        </AsyncSection>
      </SectionCard>
    </section>
  );
}
