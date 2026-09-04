import { useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { TopHeader } from "./TopHeader";
import "./AppShell.css";

export function AppShell() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  return (
    <div className="app-shell">
      <Sidebar mobileOpen={mobileNavOpen} onNavigate={() => setMobileNavOpen(false)} />
      {mobileNavOpen && <div className="app-shell-scrim" onClick={() => setMobileNavOpen(false)} />}
      <div className="main-area">
        <TopHeader onToggleSidebar={() => setMobileNavOpen((open) => !open)} />
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
