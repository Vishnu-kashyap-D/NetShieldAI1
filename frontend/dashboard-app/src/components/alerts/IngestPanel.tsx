import { useRef, useState } from "react";
import type { IngestSummaryOut } from "../../types/api";
import { useDataProvider } from "../../data/DataModeContext";
import { useSession } from "../../auth/session";
import { CAN_INGEST_TRAFFIC, roleCan } from "../../auth/permissions";
import { ApiRequestError, ApiUnavailableError } from "../../data/errors";
import { SectionCard } from "../common/SectionCard";

type Status = "idle" | "uploading" | "error" | "success";

function extractErrorMessage(err: unknown): string {
  if (err instanceof ApiRequestError) {
    const detail = err.detail;
    if (typeof detail === "object" && detail && "detail" in detail) {
      return String((detail as { detail: unknown }).detail);
    }
    return err.message;
  }
  if (err instanceof ApiUnavailableError) return err.message;
  return err instanceof Error ? err.message : "Couldn't score this file.";
}

function summaryLine(summary: IngestSummaryOut): string {
  const risk = summary.risk_level_counts;
  const parts = [`${summary.windows_scored} window(s) scored`, `${summary.alerts_written} alert(s) written`];
  if (summary.duplicates_skipped > 0) parts.push(`${summary.duplicates_skipped} duplicate(s) skipped`);
  const riskParts = [
    risk.High ? `${risk.High} High` : null,
    risk.Medium ? `${risk.Medium} Medium` : null,
    risk.Low ? `${risk.Low} Low` : null,
  ].filter(Boolean);
  if (riskParts.length > 0) parts.push(riskParts.join(", "));
  return parts.join(" — ");
}

/**
 * Real ingest UI for POST /api/ingest/csv and /api/ingest/demo -- both were already fully
 * implemented in the data layer (mockProvider.ts and realApiProvider.ts) but had no way to
 * trigger them from the dashboard itself; the only path was a script or curl. `onIngested` lets
 * the Alerts page refresh its list/stats immediately after a successful upload instead of
 * waiting for the next poll.
 */
export function IngestPanel({ onIngested }: { onIngested?: () => void }) {
  const provider = useDataProvider();
  const { analyst } = useSession();
  const canIngest = roleCan(analyst?.role, CAN_INGEST_TRAFFIC);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [includeAllWindows, setIncludeAllWindows] = useState(false);
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const [lastSummary, setLastSummary] = useState<IngestSummaryOut | null>(null);

  async function runIngest(action: () => Promise<IngestSummaryOut>) {
    setStatus("uploading");
    setError(null);
    try {
      const summary = await action();
      setLastSummary(summary);
      setStatus("success");
      setSelectedFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
      onIngested?.();
    } catch (err) {
      setStatus("error");
      setError(extractErrorMessage(err));
    }
  }

  function handleUpload() {
    if (!selectedFile) return;
    void runIngest(() => provider.ingestCsv(selectedFile, { include_all_windows: includeAllWindows }));
  }

  function handleDemoIngest() {
    void runIngest(() => provider.ingestDemo({ include_all_windows: includeAllWindows }));
  }

  if (!canIngest) {
    return (
      <SectionCard title="Ingest traffic" subtitle="Score a CSV of network flow features and add the results to the alert feed">
        <div className="role-restricted-note" role="note">
          Your role ({analyst?.role ?? "unknown"}) can't ingest traffic — this action is restricted to Threat Hunter and
          Administrator. You can still browse and investigate the alerts below.
        </div>
      </SectionCard>
    );
  }

  return (
    <SectionCard title="Ingest traffic" subtitle="Score a CSV of network flow features and add the results to the alert feed">
      <div className="ingest-panel-row">
        <input
          ref={fileInputRef}
          type="file"
          accept=".csv"
          onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
          disabled={status === "uploading"}
        />
        <label className="ingest-panel-checkbox">
          <input
            type="checkbox"
            checked={includeAllWindows}
            onChange={(e) => setIncludeAllWindows(e.target.checked)}
            disabled={status === "uploading"}
          />
          Include Low-risk windows too
        </label>
      </div>

      <div className="ingest-panel-actions">
        <button className="btn primary" onClick={handleUpload} disabled={!selectedFile || status === "uploading"}>
          {status === "uploading" ? "Scoring…" : "Upload & score"}
        </button>
        <button className="btn" onClick={handleDemoIngest} disabled={status === "uploading"}>
          {status === "uploading" ? "Scoring…" : "Score curated demo CSV"}
        </button>
      </div>

      {status === "error" && error && (
        <div className="error-state ingest-panel-message" role="alert">
          {error}
        </div>
      )}
      {status === "success" && lastSummary && (
        <div className="ingest-panel-message ingest-panel-success" role="status">
          Scored “{lastSummary.source}” — {summaryLine(lastSummary)}.
        </div>
      )}
    </SectionCard>
  );
}
