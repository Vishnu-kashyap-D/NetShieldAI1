import type { AttackCategory, RiskLevel } from "../types/api";

/**
 * The project's actual categories (cyber_ai/data.py::ATTACK_CATEGORY_MAP), Normal
 * first. Single source of truth so every filter/legend/chart in the app lists the
 * same seven values in the same order -- never invented or reordered per-component.
 */
export const CATEGORY_ORDER: readonly AttackCategory[] = [
  "Normal",
  "DoS / DDoS",
  "Port Scanning",
  "Brute Force",
  "Botnet Activity",
  "Malware Traffic",
  "Data Exfiltration",
];

/** The classifier abstained: anomalous, but no known category fits well enough to name. */
export const UNKNOWN_CATEGORY = "Unknown";

/**
 * Every value a predicted_label can take, for filters and distributions. Deliberately separate from
 * CATEGORY_ORDER, which is also the list an analyst picks a *validated* label from -- "Unknown" is something the
 * model says when unsure, never something an analyst can validate an alert as.
 */
export const PREDICTABLE_CATEGORIES: readonly string[] = [...CATEGORY_ORDER, UNKNOWN_CATEGORY];

/** Risk levels in their natural severity order (backend/app/schemas.py::AlertOut.risk_level). */
export const RISK_LEVEL_ORDER: readonly RiskLevel[] = ["High", "Medium", "Low"];
