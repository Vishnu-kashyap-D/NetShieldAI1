import type { ReactNode } from "react";
import type { AsyncStatus } from "../../hooks/usePolledAsync";

interface AsyncSectionProps<T> {
  status: AsyncStatus;
  data: T | null;
  error: Error | null;
  hasLoadedOnce: boolean;
  /** Returns true when data was fetched successfully but there's nothing to show. */
  isEmpty?: (data: T) => boolean;
  emptyLabel?: string;
  loadingLabel?: string;
  children: (data: T) => ReactNode;
}

/**
 * Standard loading / error / empty / success handling for one dashboard section,
 * so every section handles all four states the same way instead of assuming
 * data is always there.
 */
export function AsyncSection<T>({
  status,
  data,
  error,
  hasLoadedOnce,
  isEmpty,
  emptyLabel = "Nothing to show yet.",
  loadingLabel = "Loading…",
  children,
}: AsyncSectionProps<T>) {
  if (status === "loading" && !hasLoadedOnce) {
    return (
      <div className="empty-state" role="status" aria-live="polite">
        <div className="skeleton" style={{ height: 14, width: "60%", margin: "0 auto 10px" }} />
        <div className="skeleton" style={{ height: 14, width: "40%", margin: "0 auto" }} />
        <span className="visually-hidden">{loadingLabel}</span>
      </div>
    );
  }

  if (status === "error" && !hasLoadedOnce) {
    return (
      <div className="error-state" role="alert">
        Couldn't load this data{error ? `: ${error.message}` : "."}
      </div>
    );
  }

  if (!data) {
    return (
      <div className="empty-state">
        <div className="glyph">&#9676;</div>
        {emptyLabel}
      </div>
    );
  }

  if (isEmpty?.(data)) {
    return (
      <div className="empty-state">
        <div className="glyph">&#9676;</div>
        {emptyLabel}
      </div>
    );
  }

  // We have data to show (from an earlier successful load), but the most recent
  // background refresh failed -- surface that instead of silently freezing the
  // display with no indication anything is wrong (e.g. the backend went down or
  // the session expired mid-use).
  return (
    <>
      {error && (
        <div className="stale-data-banner" role="alert">
          Showing data as of the last successful update -- the most recent refresh failed
          {error.message ? `: ${error.message}` : "."}
        </div>
      )}
      {children(data)}
    </>
  );
}
