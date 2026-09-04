import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { DEFAULT_DEMO_ANALYST, useSession } from "../../auth/session";
import { BrandMark } from "../../components/common/icons";
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
            <BrandMark size={26} />
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
