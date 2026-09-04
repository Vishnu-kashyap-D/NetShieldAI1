import { NavLink } from "react-router-dom";
import { useDataProvider } from "../../data/DataModeContext";
import { usePolledAsync } from "../../hooks/usePolledAsync";
import { useSession } from "../../auth/session";
import { BrandMark, IconGrid, IconShield, IconChart, IconCheck, IconRefresh } from "../common/icons";
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
        <div className="ver">v0.4.0 · SOC redesign</div>
      </div>
    </aside>
  );
}
