import type { HealthOut } from "../../types/api";
import "./HealthBanner.css";

/**
 * Surfaces a degraded/unreachable backend clearly instead of letting the rest
 * of the dashboard silently look normal -- shown only when there's actually a
 * problem (GET /api/health reporting model_loaded=false, or the real provider
 * unable to reach the backend at all).
 */
export function HealthBanner({ health }: { health: HealthOut }) {
  if (health.model_loaded && health.status === "ok") return null;
  if (health.status.startsWith("ok")) return null; // mock provider's "ok (demo mode)"

  const isUnreachable = health.status.startsWith("unreachable");

  return (
    <div className="health-banner" role="alert">
      <span className="health-banner-icon">{isUnreachable ? "⚠" : "◐"}</span>
      <div>
        <div className="health-banner-title">
          {isUnreachable ? "Backend unreachable" : "Detection model degraded"}
        </div>
        <div className="health-banner-detail">{health.status}</div>
      </div>
    </div>
  );
}
