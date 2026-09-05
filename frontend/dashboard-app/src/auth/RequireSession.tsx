import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useSession } from "./session";

/** Gates the authenticated app shell behind the cosmetic demo session (see session.tsx). */
export function RequireSession({ children }: { children: ReactNode }) {
  const { analyst } = useSession();

  if (!analyst) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}
