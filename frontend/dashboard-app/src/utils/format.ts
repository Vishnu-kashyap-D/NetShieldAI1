/** Formats an ISO timestamp as a short, readable time (e.g. "14:32:07"). */
export function formatClockTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "--";
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** Formats an ISO timestamp as a relative "time ago" string (e.g. "3m ago", "just now"). */
export function formatRelativeTime(iso: string, now: number = Date.now()): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "--";
  const diffSeconds = Math.max(0, Math.round((now - date.getTime()) / 1000));
  if (diffSeconds < 5) return "just now";
  if (diffSeconds < 60) return `${diffSeconds}s ago`;
  const diffMinutes = Math.round(diffSeconds / 60);
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.round(diffHours / 24);
  return `${diffDays}d ago`;
}

/** Formats an ISO timestamp as a full, unambiguous date + time (e.g. "28 Aug 2026, 02:24:00"). */
export function formatFullDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "--";
  return date.toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Formats a 0..1 fraction as a percentage string, e.g. 0.9523 -> "95.2%". */
export function formatPercent(fraction: number, digits = 1): string {
  return `${(fraction * 100).toFixed(digits)}%`;
}

/** Formats a count with thousands separators. */
export function formatCount(value: number): string {
  return value.toLocaleString();
}
