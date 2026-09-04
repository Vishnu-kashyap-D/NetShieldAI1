import type { ReactNode } from "react";

interface SectionCardProps {
  /** Usually a plain string; accepts a node too (e.g. an icon + label) for a richer header. */
  title: ReactNode;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

/** The standard card shell used for every dashboard panel: title, subtitle, optional action slot. */
export function SectionCard({ title, subtitle, actions, children, className }: SectionCardProps) {
  return (
    <div className={`card${className ? ` ${className}` : ""}`}>
      <div className="card-head">
        <div>
          <div className="card-title">{title}</div>
          {subtitle && <div className="card-sub">{subtitle}</div>}
        </div>
        {actions}
      </div>
      {children}
    </div>
  );
}
