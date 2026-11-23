import { useState, type FormEvent } from "react";
import { Navigate, useNavigate, Link } from "react-router-dom";
import { useSession, type DemoAnalyst } from "../../auth/session";
import { useDataMode } from "../../data/DataModeContext";
import { describeApiError } from "../../data/errors";
import { BrandMark } from "../../components/common/icons";
import "../Login/Login.css"; // shared .field input styles
import "./Signup.css";

export function SignupPage() {
  const { analyst, signUpReal, signInDemo } = useSession();
  const { mode } = useDataMode();
  const navigate = useNavigate();
  const isReal = mode === "real";

  if (analyst) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="signup-screen">
      <div className="signup-card">
        <div className="signup-brand">
          <div className="brand-mark">
            <BrandMark size={26} />
          </div>
          <h1>Create your account</h1>
          <p>NetShield AI · Operations Console</p>
        </div>

        {isReal ? (
          <RealSignupForm
            onSuccess={() => navigate("/", { replace: true })}
            signUpReal={signUpReal}
          />
        ) : (
          <DemoSignupForm
            onSuccess={() => navigate("/", { replace: true })}
            signInDemo={signInDemo}
          />
        )}

        <div className="signup-login-link">
          Already have an account?{" "}
          <Link to="/login" id="signup-to-login-link">Sign in</Link>
        </div>
      </div>
    </div>
  );
}

function RealSignupForm({
  onSuccess,
  signUpReal,
}: {
  onSuccess: () => void;
  signUpReal: (name: string, email: string, password: string) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);

    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setPending(true);
    try {
      await signUpReal(name.trim(), email.trim(), password);
      onSuccess();
    } catch (err) {
      setError(describeApiError(err, "Could not create account."));
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <div className="field">
        <label htmlFor="signupName">Full name</label>
        <input
          id="signupName"
          type="text"
          required
          autoComplete="name"
          placeholder="Sneha Roy"
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={pending}
        />
      </div>
      <div className="field">
        <label htmlFor="signupEmail">Work email</label>
        <input
          id="signupEmail"
          type="email"
          required
          autoComplete="email"
          placeholder="you@netshield.ai"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={pending}
        />
      </div>
      <div className="field">
        <label htmlFor="signupPassword">Password <span className="field-hint">(min. 8 characters)</span></label>
        <input
          id="signupPassword"
          type="password"
          required
          autoComplete="new-password"
          placeholder="••••••••"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={pending}
        />
      </div>
      <div className="field">
        <label htmlFor="signupConfirm">Confirm password</label>
        <input
          id="signupConfirm"
          type="password"
          required
          autoComplete="new-password"
          placeholder="••••••••"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          disabled={pending}
        />
      </div>

      {error && (
        <div className="signup-error" role="alert">
          {error}
        </div>
      )}

      <button type="submit" id="signup-submit-btn" className="btn primary signup-submit" disabled={pending}>
        {pending ? "Creating account…" : "Create account"}
      </button>

      <div className="signup-note">
        New accounts get <strong>Viewer</strong> (read-only) access. Higher roles are
        created by an Administrator.
      </div>
    </form>
  );
}

function DemoSignupForm({
  onSuccess,
  signInDemo,
}: {
  onSuccess: () => void;
  signInDemo: (analyst: DemoAnalyst) => void;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    signInDemo({
      id: 0,
      name: name.trim() || "Demo User",
      email: email.trim() || "demo@netshield.ai",
      role: "Viewer",
    });
    onSuccess();
  }

  return (
    <form onSubmit={handleSubmit}>
      <div className="field">
        <label htmlFor="signupDemoName">Full name</label>
        <input
          id="signupDemoName"
          type="text"
          placeholder="Sneha Roy"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>
      <div className="field">
        <label htmlFor="signupDemoEmail">Work email</label>
        <input
          id="signupDemoEmail"
          type="email"
          placeholder="you@netshield.ai"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </div>

      <button type="submit" className="btn primary signup-submit">
        Continue as Viewer
      </button>

      <div className="signup-note">
        Demo mode — any name signs you in as a Viewer. Switch to Live API mode (header toggle once
        signed in) to use real backend registration.
      </div>
    </form>
  );
}
