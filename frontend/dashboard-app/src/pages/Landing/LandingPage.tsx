import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useSession } from "../../auth/session";
import { BrandMark } from "../../components/common/icons";
import "./LandingPage.css";

export function LandingPage() {
  const { analyst, checkingExistingSession } = useSession();
  const navigate = useNavigate();

  // Skip this page if already logged in
  useEffect(() => {
    if (!checkingExistingSession && analyst) {
      navigate("/", { replace: true });
    }
  }, [analyst, checkingExistingSession, navigate]);

  if (checkingExistingSession) {
    return (
      <div className="landing-screen">
        <div className="landing-checking">Checking session…</div>
      </div>
    );
  }

  return (
    <div className="landing-screen">
      {/* Animated background particles */}
      <div className="landing-particles">
        {Array.from({ length: 20 }).map((_, i) => (
          <div key={i} className="particle" style={{ "--i": i } as React.CSSProperties} />
        ))}
      </div>

      <div className="landing-content">
        {/* Brand */}
        <div className="landing-brand">
          <div className="landing-brand-mark">
            <BrandMark size={40} />
          </div>
          <h1 className="landing-title">NetShield AI</h1>
          <p className="landing-subtitle">Hybrid Network Intrusion Detection System</p>
          <p className="landing-tagline">
            Real-time threat detection powered by deep learning — <br />
            Autoencoder anomaly detection + BiLSTM classification
          </p>
        </div>

        {/* Feature pills */}
        <div className="landing-features">
          <span className="feature-pill">🛡️ Threat Detection</span>
          <span className="feature-pill">📊 Real-time Analytics</span>
          <span className="feature-pill">🤖 AI-Powered</span>
          <span className="feature-pill">🔍 SHAP Explainability</span>
        </div>

        {/* CTA buttons */}
        <div className="landing-actions">
          <button
            id="landing-signin-btn"
            className="landing-btn landing-btn-primary"
            onClick={() => navigate("/login")}
          >
            <span className="landing-btn-icon">→</span>
            Sign In
            <span className="landing-btn-sub">Already have an account</span>
          </button>

          <button
            id="landing-signup-btn"
            className="landing-btn landing-btn-secondary"
            onClick={() => navigate("/signup")}
          >
            <span className="landing-btn-icon">✦</span>
            Create Account
            <span className="landing-btn-sub">New to NetShield AI</span>
          </button>
        </div>

        <p className="landing-footer-note">
          Self-registered accounts get <strong>Viewer</strong> (read-only) access.
          Higher roles are created by an Administrator.
        </p>
      </div>
    </div>
  );
}
