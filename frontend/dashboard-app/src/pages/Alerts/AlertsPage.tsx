import { useMemo, useState } from "react";
import { useDataProvider } from "../../data/DataModeContext";
import { usePolledAsync } from "../../hooks/usePolledAsync";
import { PageHeader } from "../../components/common/PageHeader";
import { SectionCard } from "../../components/common/SectionCard";
import { AsyncSection } from "../../components/common/AsyncSection";
import { StatTile, IconAlerts, IconWarningTriangle, IconCheckCircle } from "../../components/dashboard/StatTile";
import { AlertsFilters, EMPTY_FILTERS, type AlertsFilterState } from "../../components/alerts/AlertsFilters";
import { AlertsTable } from "../../components/alerts/AlertsTable";
import { AlertsPagination } from "../../components/alerts/AlertsPagination";
import type { AlertOut, AlertListOut } from "../../types/api";
import "./AlertsPage.css";

const PAGE_SIZE = 10;
const POLL_MS = 15_000;

const FILTER_FIELDS = ["riskLevel", "category", "sourceFile", "batchId"] as const;

function matchesSearch(alert: AlertOut, term: string): boolean {
  if (!term) return true;
  const needle = term.trim().toLowerCase();
  if (!needle) return true;
  const haystack = [
    alert.predicted_label,
    alert.actual_category ?? "",
    alert.actual_label ?? "",
    alert.source_file,
    alert.batch_id,
    alert.risk_level,
    String(alert.id),
  ]
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}

export function AlertsPage() {
  const provider = useDataProvider();
  const [filters, setFilters] = useState<AlertsFilterState>(EMPTY_FILTERS);
  const [offset, setOffset] = useState(0);

  const listParams = useMemo(
    () => ({
      risk_level: filters.riskLevel || undefined,
      category: filters.category || undefined,
      source_file: filters.sourceFile || undefined,
      batch_id: filters.batchId || undefined,
      limit: PAGE_SIZE,
      offset,
    }),
    [filters.riskLevel, filters.category, filters.sourceFile, filters.batchId, offset],
  );

  // listAlerts() does the actual filtering/pagination server-side (or in the mock
  // provider's in-memory equivalent) -- this page never downloads everything and
  // filters client-side, except for the honestly-scoped "search this page" box.
  const alerts = usePolledAsync(
    () => provider.listAlerts(listParams),
    [
      provider,
      listParams.risk_level,
      listParams.category,
      listParams.source_file,
      listParams.batch_id,
      listParams.offset,
    ],
    POLL_MS,
  );
  const stats = usePolledAsync(() => provider.getStatsSummary(), [provider], POLL_MS);

  function updateFilters(patch: Partial<AlertsFilterState>) {
    setFilters((f) => ({ ...f, ...patch }));
    if (FILTER_FIELDS.some((field) => field in patch)) setOffset(0);
  }
  function clearFilters() {
    setFilters(EMPTY_FILTERS);
    setOffset(0);
  }

  // "The live feed" only means something on page 1 with no filter narrowing it --
  // that's the one view where a row appearing between polls represents a genuinely
  // new alert rather than the analyst having just changed what they're looking at.
  const isUnfilteredFirstPage =
    offset === 0 && !filters.riskLevel && !filters.category && !filters.sourceFile && !filters.batchId;

  const dataSourceNotice = provider.getDataSourceNotice();

  return (
    <section>
      <PageHeader title="Alerts" subtitle="Investigate detected network activity" />

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

      <SectionCard title="Investigation queue" subtitle="Newest first">
        <AlertsFilters filters={filters} onChange={updateFilters} onClear={clearFilters} />

        <div className="alerts-queue-body">
          <AsyncSection<AlertListOut>
            {...alerts}
            isEmpty={(list) => list.items.length === 0}
            emptyLabel="No alerts match these filters — try widening them."
            loadingLabel="Loading alerts…"
          >
            {(list) => {
              const visible = list.items.filter((alert) => matchesSearch(alert, filters.search));
              return (
                <>
                  {filters.search && (
                    <div className="search-scope-note">
                      {visible.length} of {list.items.length} loaded alerts match “{filters.search}” (this page only)
                    </div>
                  )}
                  {visible.length === 0 && filters.search ? (
                    <div className="empty-state">
                      <div className="glyph">&#9676;</div>
                      Nothing on this page matches “{filters.search}”. Clear the search or try another page.
                    </div>
                  ) : (
                    <AlertsTable alerts={visible} enableLiveFlash={isUnfilteredFirstPage && !filters.search} />
                  )}
                  <AlertsPagination total={list.total} limit={list.limit} offset={list.offset} onOffsetChange={setOffset} />
                </>
              );
            }}
          </AsyncSection>
        </div>
      </SectionCard>
    </section>
  );
}
