import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useSession } from "./session";

/**
 * Gates the authenticated app shell behind a real session (real mode) or the cosmetic demo
 * session (mock mode) -- see session.tsx. In real mode, a page refresh needs a round trip
 * (GET /api/auth/me) before we know whether the httpOnly cookie is still valid, so this waits
 * for `checkingExistingSession` to resolve rather than redirecting a genuinely logged-in
 * analyst to /login for one render just because React state hasn't caught up yet.
 */
export function RequireSession({ children }: { children: ReactNode }) {
  const { analyst, checkingExistingSession } = useSession();

  if (checkingExistingSession) {
    return (
      <div
        role="status"
        aria-live="polite"
        style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", color: "var(--text-mid, #888)" }}
      >
        Checking your session…
      </div>
    );
  }

  if (!analyst) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}
