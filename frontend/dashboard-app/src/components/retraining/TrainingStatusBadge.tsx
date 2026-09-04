import type { RetrainStatus } from "../../types/api";

const CLASS_BY_STATUS: Record<RetrainStatus, string> = {
  running: "status-running",
  completed: "status-completed",
  failed: "status-failed",
};

/** Consistent visual treatment for a TrainingRunOut.status value -- no invented states beyond running/completed/failed. */
export function TrainingStatusBadge({ status }: { status: RetrainStatus }) {
  return (
    <span className={`badge ${CLASS_BY_STATUS[status]}`}>
      {status === "running" && <span className="dot pulse" />}
      {status}
    </span>
  );
}
