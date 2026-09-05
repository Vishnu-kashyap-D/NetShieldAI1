import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { UserOut } from "../types/api";
import { useDataProvider } from "../data/DataModeContext";

/**
 * Real API mode: a real session, verified server-side (backend/app/auth.py) via an httpOnly
 * cookie -- `role` is a fact about the account, assigned at creation, never chosen here.
 * Mock/demo mode: cosmetic, session-only auth mirroring the old Phase 1 prototype's behavior
 * (any name/email/password signs a visitor in, nothing is verified, nothing persists past this
 * browser tab) -- the role dropdown on the login screen only exists in this mode, precisely
 * because it's fake and choosing what to demo is the point.
 */
export type DemoAnalyst = UserOut;

interface SessionState {
  analyst: DemoAnalyst | null;
  /** True until the initial check for an existing real-mode session (GET /api/auth/me) resolves.
   * Stays false forever in mock mode -- there's nothing to await there. */
  checkingExistingSession: boolean;
  /** Mock mode only: instantly "signs in" as whatever identity the demo login form built,
   * no server involved. Calling this in real mode would be a bug -- see signInReal. */
  signInDemo: (analyst: DemoAnalyst) => void;
  /** Real mode only: verifies email/password against the backend; throws on failure (the
   * Login page shows the thrown error's message rather than swallowing it). */
  signInReal: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const STORAGE_KEY = "netshield.demoSession";

function readStoredMockSession(): DemoAnalyst | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as DemoAnalyst) : null;
  } catch {
    return null;
  }
}

function writeStoredMockSession(analyst: DemoAnalyst | null): void {
  try {
    if (analyst) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(analyst));
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // sessionStorage unavailable -- session just won't survive a refresh.
  }
}

const SessionContext = createContext<SessionState | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const provider = useDataProvider();
  const isReal = provider.mode === "real";

  const [analyst, setAnalyst] = useState<DemoAnalyst | null>(() => (isReal ? null : readStoredMockSession()));
  const [checkingExistingSession, setCheckingExistingSession] = useState(isReal);

  // Real mode: a page refresh loses all React state but the httpOnly session cookie survives
  // (the browser keeps sending it), so check whether it's still valid instead of assuming the
  // visitor is signed out. Mock mode has nothing to check -- its "session" is the sessionStorage
  // read above, already resolved synchronously.
  useEffect(() => {
    if (!isReal) {
      setCheckingExistingSession(false);
      return;
    }
    let cancelled = false;
    setCheckingExistingSession(true);
    provider
      .getCurrentUser()
      .then((user) => {
        if (!cancelled) setAnalyst(user);
      })
      .catch(() => {
        if (!cancelled) setAnalyst(null);
      })
      .finally(() => {
        if (!cancelled) setCheckingExistingSession(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider, isReal]);

  const value = useMemo<SessionState>(
    () => ({
      analyst,
      checkingExistingSession,
      signInDemo: (next) => {
        writeStoredMockSession(next);
        setAnalyst(next);
      },
      signInReal: async (email, password) => {
        const user = await provider.login({ email, password }); // throws on 401 -- Login.tsx surfaces the message
        setAnalyst(user);
      },
      signOut: async () => {
        if (isReal) {
          await provider.logout().catch(() => {
            // Logging out is best-effort from the UI's perspective -- even if the request fails
            // (e.g. the backend is briefly unreachable), the analyst still expects to be signed
            // out locally rather than stuck on a dead session they can't get back into.
          });
        } else {
          writeStoredMockSession(null);
        }
        setAnalyst(null);
      },
    }),
    [analyst, checkingExistingSession, provider, isReal],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used within a SessionProvider");
  return ctx;
}

/** Mock mode only: a generic default identity for the "Continue as demo analyst" shortcut. */
export const DEFAULT_DEMO_ANALYST: DemoAnalyst = {
  id: 0,
  name: "Demo Analyst",
  email: "demo.analyst@netshield.ai",
  role: "Security Analyst",
};
