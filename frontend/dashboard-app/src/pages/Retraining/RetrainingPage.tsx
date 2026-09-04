import { useEffect, useRef, useState } from "react";
import type { TrainingRunOut } from "../../types/api";
import { useDataProvider } from "../../data/DataModeContext";
import { useSession } from "../../auth/session";
import { usePolledAsync } from "../../hooks/usePolledAsync";
import { ApiUnavailableError, RetrainAlreadyRunningError } from "../../data/errors";
import { PageHeader } from "../../components/common/PageHeader";
import { SectionCard } from "../../components/common/SectionCard";
import { TrainingStatusBadge } from "../../components/retraining/TrainingStatusBadge";
import { TrainingMetrics } from "../../components/retraining/TrainingMetrics";
import { formatFullDateTime } from "../../utils/format";
import "./RetrainingPage.css";

const POLL_INTERVAL_MS = 3000;

function sortNewestFirst(runs: TrainingRunOut[]): TrainingRunOut[] {
  return [...runs].sort((a, b) => b.started_at.localeCompare(a.started_at));
}

export function RetrainingPage() {
  const provider = useDataProvider();
  const { analyst } = useSession();

  const [runs, setRuns] = useState<TrainingRunOut[] | null>(null);
  const [listStatus, setListStatus] = useState<"loading" | "success" | "error">("loading");
  const [listError, setListError] = useState<Error | null>(null);

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [triggerState, setTriggerState] = useState<"idle" | "triggering" | "error">("idle");
  const [triggerError, setTriggerError] = useState<string | null>(null);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Feedback rows recorded so far -- reuses the existing global feedback listing
  // (the only feedback-count signal the real API actually exposes) as context for
  // "is there anything new to retrain on", not a fabricated metric.
  const feedbackCount = usePolledAsync(() => provider.listFeedback(), [provider]);

  function stopPolling() {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }

  async function refreshRuns(): Promise<TrainingRunOut[]> {
    const list = sortNewestFirst(await provider.listRetrainRuns());
    setRuns(list);
    setListStatus("success");
    setListError(null);
    return list;
  }

  function startPolling() {
    stopPolling();
    intervalRef.current = setInterval(async () => {
      try {
        const list = await refreshRuns();
        const latest = list[0];
        if (!latest || latest.status !== "running") stopPolling();
      } catch (err) {
        setListStatus("error");
        setListError(err instanceof Error ? err : new Error(String(err)));
        stopPolling();
      }
    }, POLL_INTERVAL_MS);
  }

  // Re-fetch from scratch whenever the active provider changes (DEMO <-> LIVE API),
  // so switching modes never leaves the other mode's run list on screen.
  useEffect(() => {
    let cancelled = false;
    setRuns(null);
    setListStatus("loading");
    setListError(null);
    stopPolling();

    (async () => {
      try {
        const list = await refreshRuns();
        if (cancelled) return;
        const latest = list[0];
        if (latest && latest.status === "running") startPolling();
      } catch (err) {
        if (cancelled) return;
        setListStatus("error");
        setListError(err instanceof Error ? err : new Error(String(err)));
      }
    })();

    return () => {
      cancelled = true;
      stopPolling();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider]);

  const latestRun = runs?.[0] ?? null;
  const aRunIsActive = latestRun?.status === "running";

  async function handleConfirmTrigger() {
    setTriggerState("triggering");
    setTriggerError(null);
    try {
      const run = await provider.triggerRetrain({ triggered_by: analyst?.name ?? undefined });
      setRuns((prev) => [run, ...(prev ?? []).filter((r) => r.id !== run.id)]);
      setListStatus("success");
      setTriggerState("idle");
      setConfirmOpen(false);
      startPolling();
    } catch (err) {
      setTriggerState("error");
      if (err instanceof RetrainAlreadyRunningError) {
        setTriggerError(`Training run ${err.runId} is already in progress — watching it below.`);
        startPolling();
      } else if (err instanceof ApiUnavailableError) {
        setTriggerError(err.message);
      } else {
        setTriggerError(err instanceof Error ? err.message : "Could not start retraining.");
      }
    }
  }

  const dataSourceNotice = provider.getDataSourceNotice();
  const isMock = provider.mode === "mock";

  return (
    <section>
      <PageHeader title="Retraining" subtitle="Feedback-driven retraining of the detection model" />

      {dataSourceNotice && <div className="data-source-notice">{dataSourceNotice}</div>}

      <SectionCard title="Start a retraining run" subtitle="Runs cyber_ai.train in the background with accumulated feedback">
        <p className="retrain-explainer">
          Triggering retraining starts a background training job using every analyst correction submitted so far
          {feedbackCount.data ? ` (${feedbackCount.data.length} recorded)` : ""}. It does not run instantly —
          {isMock
            ? " in demo mode this is simulated on a short timer, clearly marked as synthetic below."
            : " the real backend runs it as a background subprocess and can take several minutes."}{" "}
          The backend refuses a second run while one is already in progress.
        </p>

        {aRunIsActive ? (
          <div className="retrain-active-note">
            A training run (#{latestRun!.id}) is already in progress — see its status below.
          </div>
        ) : !confirmOpen ? (
          <button className="btn primary" onClick={() => setConfirmOpen(true)}>
            Start Retraining
          </button>
        ) : (
          <div className="retrain-confirm">
            <p>
              This will start a real background training run using the accumulated feedback above. Are you sure you
              want to proceed?
            </p>
            <div className="retrain-confirm-actions">
              <button className="btn primary" onClick={handleConfirmTrigger} disabled={triggerState === "triggering"}>
                {triggerState === "triggering" ? "Starting…" : "Yes, start retraining"}
              </button>
              <button className="btn" onClick={() => setConfirmOpen(false)} disabled={triggerState === "triggering"}>
                Cancel
              </button>
            </div>
          </div>
        )}

        {triggerState === "error" && triggerError && (
          <div className="error-state retrain-trigger-error" role="alert">
            {triggerError}
          </div>
        )}
      </SectionCard>

      <SectionCard title="Current status" subtitle="The most recent training run known to this data source">
        {listStatus === "loading" && !runs && (
          <div className="empty-state" role="status" aria-live="polite">
            <div className="skeleton" style={{ height: 14, width: "40%", margin: "0 auto" }} />
          </div>
        )}
        {listStatus === "error" && !runs && (
          <div className="error-state" role="alert">
            Couldn't load training status{listError ? `: ${listError.message}` : "."}
          </div>
        )}
        {runs && runs.length === 0 && (
          <div className="empty-state">
            <div className="glyph">&#9676;</div>
            No retraining runs yet — start one above once feedback has been submitted.
          </div>
        )}
        {latestRun && (
          <div className="retrain-current">
            <div className="retrain-current-head">
              <TrainingStatusBadge status={latestRun.status} />
              <span className="retrain-current-id">Run #{latestRun.id}</span>
              {latestRun.status === "running" && <span className="retrain-current-live">Training in progress…</span>}
            </div>
            <div className="retrain-current-grid">
              <div>
                <span className="retrain-field-label">Triggered by</span>
                <span className="retrain-field-value">{latestRun.triggered_by ?? "Not available"}</span>
              </div>
              <div>
                <span className="retrain-field-label">Feedback rows used</span>
                <span className="retrain-field-value">{latestRun.feedback_rows_used ?? "Not available"}</span>
              </div>
              <div>
                <span className="retrain-field-label">Started</span>
                <span className="retrain-field-value">{formatFullDateTime(latestRun.started_at)}</span>
              </div>
              <div>
                <span className="retrain-field-label">Finished</span>
                <span className="retrain-field-value">
                  {latestRun.finished_at ? formatFullDateTime(latestRun.finished_at) : "Not finished yet"}
                </span>
              </div>
            </div>

            {latestRun.status === "failed" && latestRun.error && (
              <div className="error-state retrain-run-error" role="alert">
                {latestRun.error}
              </div>
            )}

            {latestRun.status === "completed" && latestRun.metrics && (
              <div className="retrain-metrics-block">
                <div className="retrain-metrics-title">
                  Training metrics
                  {isMock && <span className="badge neutral retrain-simulated-tag">Simulated</span>}
                </div>
                <TrainingMetrics metrics={latestRun.metrics} />
              </div>
            )}
          </div>
        )}
      </SectionCard>

      {runs && runs.length > 1 && (
        <SectionCard title="Run history" subtitle="All retraining runs known to this data source">
          <div className="retrain-history">
            {runs.map((run) => (
              <div className="retrain-history-row" key={run.id}>
                <span className="retrain-history-id">#{run.id}</span>
                <TrainingStatusBadge status={run.status} />
                <span className="retrain-history-time">{formatFullDateTime(run.started_at)}</span>
                <span className="retrain-history-feedback">{run.feedback_rows_used ?? "—"} feedback rows</span>
              </div>
            ))}
          </div>
        </SectionCard>
      )}
    </section>
  );
}
