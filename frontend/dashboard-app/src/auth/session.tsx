import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

/**
 * Cosmetic, session-only demo authentication -- mirrors the login behavior of
 * frontend/netshield-dashboard.html (Phase 1 prototype): any name/email/password
 * signs a visitor in, nothing is verified against a server, and nothing persists
 * past this browser tab. Real credential verification and role-based access
 * control are out of scope here, same as that prototype states.
 */
export interface DemoAnalyst {
  name: string;
  email: string;
  role: string;
}

interface SessionState {
  analyst: DemoAnalyst | null;
  signIn: (analyst: DemoAnalyst) => void;
  signOut: () => void;
}

const STORAGE_KEY = "netshield.demoSession";

function readStoredSession(): DemoAnalyst | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as DemoAnalyst) : null;
  } catch {
    return null;
  }
}

function writeStoredSession(analyst: DemoAnalyst | null): void {
  try {
    if (analyst) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(analyst));
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // sessionStorage unavailable -- session just won't survive a refresh.
  }
}

const SessionContext = createContext<SessionState | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [analyst, setAnalyst] = useState<DemoAnalyst | null>(() => readStoredSession());

  const value = useMemo<SessionState>(
    () => ({
      analyst,
      signIn: (next) => {
        writeStoredSession(next);
        setAnalyst(next);
      },
      signOut: () => {
        writeStoredSession(null);
        setAnalyst(null);
      },
    }),
    [analyst],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used within a SessionProvider");
  return ctx;
}

/** A generic default identity for the "Continue as demo analyst" shortcut. */
export const DEFAULT_DEMO_ANALYST: DemoAnalyst = {
  name: "Demo Analyst",
  email: "demo.analyst@netshield.ai",
  role: "Security Analyst",
};
