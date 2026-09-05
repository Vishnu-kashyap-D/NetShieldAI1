import { useEffect, useRef, useState } from "react";

export type AsyncStatus = "loading" | "error" | "success";

export interface PolledAsyncResult<T> {
  status: AsyncStatus;
  data: T | null;
  error: Error | null;
  /** True once the first successful fetch has completed -- lets a poll refresh keep the previous render instead of flashing back to a loading state. */
  hasLoadedOnce: boolean;
  refresh: () => void;
}

function shallowEqual(a: unknown[], b: unknown[]): boolean {
  return a.length === b.length && a.every((value, index) => Object.is(value, b[index]));
}

/**
 * Runs an async fetch on mount, on every dependency change, and (optionally) on
 * a fixed interval, exposing loading/error/success state so components never
 * have to assume data already exists.
 *
 * A background poll or a manual refresh() keeps whatever was last rendered on
 * screen (status stays "success", old data stays visible) rather than bouncing
 * back to a loading skeleton every cycle. A real *dependency* change (e.g. the
 * active DataProvider itself changing when the demo/real mode toggle is used)
 * is treated as a brand-new query instead: it resets to loading and clears the
 * previous result, so switching modes never leaves stale data from the other
 * provider silently on screen under the new mode's banner.
 */
export function usePolledAsync<T>(
  fetcher: () => Promise<T>,
  deps: unknown[],
  intervalMs?: number,
): PolledAsyncResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [status, setStatus] = useState<AsyncStatus>("loading");
  const hasLoadedOnce = useRef(false);
  const prevDepsRef = useRef<unknown[] | null>(null);
  const [tick, forceTick] = useState(0);

  useEffect(() => {
    const depsChanged = prevDepsRef.current === null || !shallowEqual(prevDepsRef.current, deps);
    prevDepsRef.current = deps;

    let cancelled = false;

    if (depsChanged) {
      hasLoadedOnce.current = false;
      setStatus("loading");
      setData(null);
      setError(null);
    }

    async function run() {
      if (!hasLoadedOnce.current) setStatus("loading");
      try {
        const result = await fetcher();
        if (cancelled) return;
        setData(result);
        setError(null);
        setStatus("success");
        hasLoadedOnce.current = true;
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err : new Error(String(err)));
        if (!hasLoadedOnce.current) setStatus("error");
      }
    }

    void run();
    let intervalId: ReturnType<typeof setInterval> | undefined;
    if (intervalMs) intervalId = setInterval(run, intervalMs);

    return () => {
      cancelled = true;
      if (intervalId) clearInterval(intervalId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  return {
    status,
    data,
    error,
    hasLoadedOnce: hasLoadedOnce.current,
    refresh: () => forceTick((n) => n + 1),
  };
}
