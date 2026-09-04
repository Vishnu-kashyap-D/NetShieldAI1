import { NavLink } from "react-router-dom";
import { useDataProvider } from "../../data/DataModeContext";
import { usePolledAsync } from "../../hooks/usePolledAsync";
import { useSession } from "../../auth/session";
import "./Sidebar.css";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", end: true, icon: <IconGrid /> },
  { to: "/alerts", label: "Alerts", icon: <IconShield /> },
  { to: "/analytics", label: "Analytics", icon: <IconChart /> },
  { to: "/feedback", label: "Feedback", icon: <IconCheck /> },
  { to: "/retraining", label: "Retraining", icon: <IconRefresh /> },
];

function healthPresentation(status: string, modelLoaded: boolean): { label: string; tone: "ok" | "warn" } {
  if (modelLoaded && status === "ok") return { label: "Operational", tone: "ok" };
  if (status.startsWith("ok")) return { label: "Operational (demo)", tone: "ok" };
  if (status.startsWith("unreachable")) return { label: "Backend unreachable", tone: "warn" };
  return { label: "Degraded", tone: "warn" };
}

export function Sidebar({ mobileOpen, onNavigate }: { mobileOpen: boolean; onNavigate: () => void }) {
  const provider = useDataProvider();
  const { analyst } = useSession();
  const health = usePolledAsync(() => provider.getHealth(), [provider], 15000);

  const initials = analyst?.name
    .split(" ")
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();

  const presentation = health.data ? healthPresentation(health.data.status, health.data.model_loaded) : null;

  return (
    <aside className={`sidebar${mobileOpen ? " sidebar--open" : ""}`}>
      <div className="brand">
        <div className="brand-mark">
          <BrandMark />
        </div>
        <span className="brand-name">NetShield AI</span>
      </div>

      <nav className="nav-list">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            onClick={onNavigate}
            className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>

      {analyst && (
        <div className="sidebar-user">
          <div className="avatar">{initials}</div>
          <div className="who">
            <div className="name">{analyst.name}</div>
            <div className="role">{analyst.role}</div>
          </div>
        </div>
      )}

      <div className="sidebar-status">
        <div className="label">System status</div>
        {presentation ? (
          <>
            <div className={`state state--${presentation.tone}`}>
              <span className={`dot pulse dot--${presentation.tone}`} />
              <span>{presentation.label}</span>
            </div>
            <div className="detail">{health.data?.status}</div>
          </>
        ) : (
          <div className="detail">Checking backend…</div>
        )}
        <div className="ver">v0.3.0 · Phase 3</div>
      </div>
    </aside>
  );
}

function BrandMark() {
  return (
    <svg viewBox="0 0 24 24" fill="none" width="19" height="19">
      <path d="M12 2L4 5v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V5l-8-3z" fill="#2E1065" />
      <path d="M9 12l2 2 4-4" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function IconGrid() {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </svg>
  );
}

function IconShield() {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 01-3.4 0" />
    </svg>
  );
}

function IconChart() {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 3v18h18" />
      <path d="M7 16l4-5 3 3 5-7" />
    </svg>
  );
}

function IconCheck() {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 12l2 2 4-4" />
      <circle cx="12" cy="12" r="9" />
    </svg>
  );
}

function IconRefresh() {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12a9 9 0 10-3.5 7.1" />
      <path d="M21 4v6h-6" />
    </svg>
  );
}
