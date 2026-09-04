import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { getDataProvider, resetDataProviderCache } from "./index";
import { clearDataModeOverride, getDataMode, setDataMode, type DataMode } from "./config";
import type { DataProvider } from "./DataProvider";

interface DataModeState {
  mode: DataMode;
  provider: DataProvider;
  /** Switches mode at runtime (persists as a localStorage override) and re-resolves the provider. */
  setMode: (mode: DataMode) => void;
  /** Drops any runtime override, falling back to VITE_DATA_MODE / the default. */
  clearOverride: () => void;
}

const DataModeContext = createContext<DataModeState | null>(null);

/**
 * Makes the active DataProvider available to the component tree and reactive:
 * switching modes re-renders every consumer with a freshly resolved provider,
 * so the UI never needs a full page reload to move between DEMO/MOCK and REAL
 * API mode. Components should read the provider via useDataProvider(), never
 * by importing MockDataProvider/RealApiProvider directly.
 */
export function DataModeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<DataMode>(() => getDataMode());

  const value = useMemo<DataModeState>(
    () => ({
      mode,
      provider: getDataProvider(),
      setMode: (next) => {
        setDataMode(next);
        resetDataProviderCache();
        setModeState(next);
      },
      clearOverride: () => {
        clearDataModeOverride();
        resetDataProviderCache();
        setModeState(getDataMode());
      },
    }),
    [mode],
  );

  return <DataModeContext.Provider value={value}>{children}</DataModeContext.Provider>;
}

function useDataModeState(): DataModeState {
  const ctx = useContext(DataModeContext);
  if (!ctx) throw new Error("useDataMode/useDataProvider must be used within a DataModeProvider");
  return ctx;
}

/** The active DataProvider. Re-resolved whenever the data mode changes. */
export function useDataProvider(): DataProvider {
  return useDataModeState().provider;
}

/** The current data mode plus setters -- for the mode toggle in the top header. */
export function useDataMode(): Pick<DataModeState, "mode" | "setMode" | "clearOverride"> {
  const { mode, setMode, clearOverride } = useDataModeState();
  return { mode, setMode, clearOverride };
}
