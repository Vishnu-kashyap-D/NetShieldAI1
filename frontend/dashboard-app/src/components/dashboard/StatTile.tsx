import type { ReactNode } from "react";
import "./StatTile.css";

interface StatTileProps {
  icon: ReactNode;
  tone: "blue" | "red" | "orange" | "green" | "purple";
  value: string;
  label: string;
  badge?: string;
}

// A tile whose tone corresponds to a severity level gets a matching top stripe, so
// severity reads as a shape (scannable in peripheral vision), not only as a color
// inside the icon chip. "blue"/"purple" tiles (Total alerts, etc.) aren't a severity,
// so they stay neutral -- no fabricated stripe on a number that isn't risk-graded.
const STRIPE_BY_TONE: Partial<Record<StatTileProps["tone"], string>> = {
  red: "stat-card--high",
  orange: "stat-card--medium",
  green: "stat-card--low",
};

export function StatTile({ icon, tone, value, label, badge }: StatTileProps) {
  const stripeClass = STRIPE_BY_TONE[tone];
  return (
    <div className={`stat-card${stripeClass ? ` ${stripeClass}` : ""}`}>
      <div className="stat-card-top">
        <div className={`icon-chip icon-chip--${tone}`}>{icon}</div>
        {badge && <span className="badge neutral">{badge}</span>}
      </div>
      <div className="stat-card-value">{value}</div>
      <div className="stat-card-label">{label}</div>
    </div>
  );
}

export function IconAlerts() {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2">
      <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 01-3.4 0" />
    </svg>
  );
}

export function IconWarningTriangle() {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

export function IconCheckCircle() {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2">
      <circle cx="12" cy="12" r="10" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}
