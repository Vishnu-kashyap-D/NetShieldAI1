import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { DEFAULT_DEMO_ANALYST, useSession } from "../../auth/session";
import "./Login.css";

const ROLES = ["Security Analyst", "Threat Hunter", "Administrator", "Viewer"];

export function Login() {
  const { analyst, signIn } = useSession();
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState(ROLES[0]);

  // Dashboard is always the default landing page after signing in -- this is not a
  // "return to whatever page you were trying to reach" flow.
  if (analyst) {
    return <Navigate to="/" replace />;
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    signIn({ name: name.trim() || DEFAULT_DEMO_ANALYST.name, email: email.trim() || DEFAULT_DEMO_ANALYST.email, role });
    navigate("/", { replace: true });
  }

  function handleDemoLogin() {
    signIn(DEFAULT_DEMO_ANALYST);
    navigate("/", { replace: true });
  }

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-brand">
          <div className="brand-mark">
            <svg viewBox="0 0 24 24" fill="none" width="26" height="26">
              <path d="M12 2L4 5v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V5l-8-3z" fill="#2E1065" />
              <path d="M9 12l2 2 4-4" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <h1>Sign in to NetShield AI</h1>
          <p>Hybrid NIDS · Operations Console</p>
        </div>

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
            <select id="loginRole" value={role} onChange={(e) => setRole(e.target.value)}>
              {ROLES.map((r) => (
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
          Demo build — any name and password will sign you in. Real credential verification and role-based access
          control are not implemented yet.
        </div>
      </div>
    </div>
  );
}
