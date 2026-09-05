import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { DEFAULT_DEMO_ANALYST, useSession, type DemoAnalyst } from "../../auth/session";
import { useDataMode } from "../../data/DataModeContext";
import type { UserRole } from "../../types/api";
import { BrandMark } from "../../components/common/icons";
import "./Login.css";

const DEMO_ROLES: UserRole[] = ["Security Analyst", "Threat Hunter", "Administrator", "Viewer"];

export function Login() {
  const { analyst, signInDemo, signInReal } = useSession();
  const { mode } = useDataMode();
  const navigate = useNavigate();
  const isReal = mode === "real";

  // Dashboard is always the default landing page after signing in -- this is not a
  // "return to whatever page you were trying to reach" flow.
  if (analyst) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-brand">
          <div className="brand-mark">
            <BrandMark size={26} />
          </div>
          <h1>Sign in to NetShield AI</h1>
          <p>Hybrid NIDS · Operations Console</p>
        </div>

        {isReal ? (
          <RealLoginForm onSuccess={() => navigate("/", { replace: true })} signInReal={signInReal} />
        ) : (
          <DemoLoginForm
            onSuccess={() => navigate("/", { replace: true })}
            signInDemo={signInDemo}
          />
        )}
      </div>
    </div>
  );
}

/** Real API mode: real credentials, checked against backend/app/auth.py. */
function RealLoginForm({
  onSuccess,
  signInReal,
}: {
  onSuccess: () => void;
  signInReal: (email: string, password: string) => Promise<void>;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await signInReal(email, password);
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not sign in.");
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="loginEmail">Work email</label>
          <input
            id="loginEmail"
            type="email"
            required
            autoComplete="username"
            placeholder="you@netshield.ai"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={pending}
          />
        </div>
        <div className="field">
          <label htmlFor="loginPassword">Password</label>
          <input
            id="loginPassword"
            type="password"
            required
            autoComplete="current-password"
            placeholder="••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={pending}
          />
        </div>

        {error && (
          <div className="login-error" role="alert">
            {error}
          </div>
        )}

        <button type="submit" className="btn primary login-submit" disabled={pending}>
          {pending ? "Signing in…" : "Sign in"}
        </button>
      </form>

      <div className="login-note">
        Real accounts, verified by the backend. Your role (Viewer / Security Analyst / Threat Hunter /
        Administrator) is set on your account and determines what you can do — it isn't something you choose here.
        There's no public sign-up; an Administrator creates accounts. On a fresh database, four demo accounts exist
        (admin@netshield.ai, analyst@netshield.ai, hunter@netshield.ai, viewer@netshield.ai — see backend/README.md
        for the shared password).
      </div>
    </>
  );
}

/** Mock/demo mode: cosmetic only, matching the old Phase 1 prototype's behavior exactly --
 * any input signs a visitor in, and the role dropdown is real precisely because this mode
 * is fake: picking a role here is how a presenter demos what each role's UI looks like. */
function DemoLoginForm({
  onSuccess,
  signInDemo,
}: {
  onSuccess: () => void;
  signInDemo: (analyst: DemoAnalyst) => void;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>(DEMO_ROLES[0]);

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    signInDemo({
      id: 0,
      name: name.trim() || DEFAULT_DEMO_ANALYST.name,
      email: email.trim() || DEFAULT_DEMO_ANALYST.email,
      role,
    });
    onSuccess();
  }

  function handleDemoLogin() {
    signInDemo(DEFAULT_DEMO_ANALYST);
    onSuccess();
  }

  return (
    <>
      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="loginName">Full name</label>
          <input id="loginName" type="text" placeholder="Sneha Roy" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="loginEmail">Work email</label>
          <input
            id="loginEmail"
            type="email"
            placeholder="you@netshield.ai"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="loginPassword">Password</label>
          <input
            id="loginPassword"
            type="password"
            placeholder="••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="loginRole">Role</label>
          <select id="loginRole" value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
            {DEMO_ROLES.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </div>
        <button type="submit" className="btn primary login-submit">
          Sign in
        </button>
        <button type="button" className="btn login-demo" onClick={handleDemoLogin}>
          Continue as demo analyst
        </button>
      </form>

      <div className="login-note">
        Demo mode — any name and password will sign you in, and the role above is just for previewing that role's
        view. This mode is currently selected because it's either the default or a saved preference from this
        browser; the "Demo / Live API" toggle in the header (visible once signed in) switches to real,
        backend-verified accounts with real role enforcement.
      </div>
    </>
  );
}
