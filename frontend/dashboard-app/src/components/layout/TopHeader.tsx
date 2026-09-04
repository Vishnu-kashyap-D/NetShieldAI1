import { useNavigate } from "react-router-dom";
import { useDataMode } from "../../data/DataModeContext";
import { useSession } from "../../auth/session";
import { IconMenu } from "../common/icons";
import "./TopHeader.css";

export function TopHeader({ onToggleSidebar }: { onToggleSidebar: () => void }) {
  const { mode, setMode } = useDataMode();
  const { analyst, signOut } = useSession();
  const navigate = useNavigate();

  function handleSignOut() {
    signOut();
    navigate("/login");
  }

  return (
    <header className="top-header">
      <button className="menu-btn" onClick={onToggleSidebar} aria-label="Toggle navigation">
        <IconMenu />
      </button>

      <div className="top-header-spacer" />

      <div
        className={`mode-indicator mode-indicator--${mode}`}
        title={
          mode === "mock"
            ? "Showing locally-generated demo data, not live output from the trained model."
            : "Showing live data read from the FastAPI backend."
        }
      >
        <span className="dot pulse" />
        <span>{mode === "mock" ? "DEMO MODE" : "LIVE API"}</span>
      </div>

      <div className="mode-toggle" role="group" aria-label="Data source">
        <button className={mode === "mock" ? "active" : ""} onClick={() => setMode("mock")}>
          Demo
        </button>
        <button className={mode === "real" ? "active" : ""} onClick={() => setMode("real")}>
          Live API
        </button>
      </div>

      {analyst && (
        <div className="analyst-chip">
          <div className="analyst-chip-who">
            <div className="name">{analyst.name}</div>
            <div className="role">{analyst.role}</div>
          </div>
          <button className="btn" onClick={handleSignOut}>
            Sign out
          </button>
        </div>
      )}
    </header>
  );
}
