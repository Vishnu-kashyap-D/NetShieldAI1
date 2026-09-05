/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "mock" or "real". Defaults to "mock" when unset. See src/data/config.ts. */
  readonly VITE_DATA_MODE?: string;
  /** Base URL of the FastAPI backend, e.g. http://localhost:8000. Only used in "real" mode. */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
