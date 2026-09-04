import { useEffect, useState, type KeyboardEvent } from "react";
import type { AttackCategory, RiskLevel } from "../../types/api";
import { CATEGORY_ORDER, RISK_LEVEL_ORDER } from "../../constants/taxonomy";
import "./AlertsFilters.css";

export interface AlertsFilterState {
  riskLevel: RiskLevel | "";
  category: AttackCategory | "";
  /** Exact match, per GET /api/alerts's source_file filter (backend/app/routers/alerts.py) -- not a substring search. */
  sourceFile: string;
  /** Exact match, same as source_file. */
  batchId: string;
  /** Client-side only -- filters the currently loaded page, not the full backend result set. */
  search: string;
}

export const EMPTY_FILTERS: AlertsFilterState = {
  riskLevel: "",
  category: "",
  sourceFile: "",
  batchId: "",
  search: "",
};

interface AlertsFiltersProps {
  filters: AlertsFilterState;
  onChange: (patch: Partial<AlertsFilterState>) => void;
  onClear: () => void;
}

function hasActiveFilter(filters: AlertsFilterState): boolean {
  return Object.values(filters).some((v) => v !== "");
}

export function AlertsFilters({ filters, onChange, onClear }: AlertsFiltersProps) {
  // source_file / batch_id are exact-match backend filters (not a live substring
  // search), so typing shouldn't fire a request per keystroke -- these apply on
  // blur/Enter instead, via local draft state kept in sync with the real value.
  const [sourceDraft, setSourceDraft] = useState(filters.sourceFile);
  const [batchDraft, setBatchDraft] = useState(filters.batchId);

  useEffect(() => setSourceDraft(filters.sourceFile), [filters.sourceFile]);
  useEffect(() => setBatchDraft(filters.batchId), [filters.batchId]);

  function commitSource() {
    if (sourceDraft.trim() !== filters.sourceFile) onChange({ sourceFile: sourceDraft.trim() });
  }
  function commitBatch() {
    if (batchDraft.trim() !== filters.batchId) onChange({ batchId: batchDraft.trim() });
  }
  function onEnter(commit: () => void) {
    return (e: KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") commit();
    };
  }

  return (
    <div className="alerts-filters">
      <div className="search-input">
        <svg viewBox="0 0 24 24" fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="text"
          placeholder="Search this page (category, source, batch, id)…"
          value={filters.search}
          onChange={(e) => onChange({ search: e.target.value })}
          aria-label="Search alerts currently loaded on this page"
        />
      </div>

      <select
        value={filters.riskLevel}
        onChange={(e) => onChange({ riskLevel: e.target.value as RiskLevel | "" })}
        aria-label="Filter by risk level"
      >
        <option value="">All severities</option>
        {RISK_LEVEL_ORDER.map((level) => (
          <option key={level} value={level}>
            {level}
          </option>
        ))}
      </select>

      <select
        value={filters.category}
        onChange={(e) => onChange({ category: e.target.value as AttackCategory | "" })}
        aria-label="Filter by predicted category"
      >
        <option value="">All categories</option>
        {CATEGORY_ORDER.map((category) => (
          <option key={category} value={category}>
            {category}
          </option>
        ))}
      </select>

      <input
        type="text"
        className="exact-filter"
        placeholder="Source file (exact)"
        value={sourceDraft}
        onChange={(e) => setSourceDraft(e.target.value)}
        onBlur={commitSource}
        onKeyDown={onEnter(commitSource)}
        aria-label="Filter by exact source file name"
      />

      <input
        type="text"
        className="exact-filter"
        placeholder="Batch ID (exact)"
        value={batchDraft}
        onChange={(e) => setBatchDraft(e.target.value)}
        onBlur={commitBatch}
        onKeyDown={onEnter(commitBatch)}
        aria-label="Filter by exact batch ID"
      />

      <button className="btn" onClick={onClear} disabled={!hasActiveFilter(filters)}>
        Clear filters
      </button>
    </div>
  );
}
