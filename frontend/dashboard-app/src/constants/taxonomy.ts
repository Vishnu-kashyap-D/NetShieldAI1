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

/** Risk levels in their natural severity order (backend/app/schemas.py::AlertOut.risk_level). */
export const RISK_LEVEL_ORDER: readonly RiskLevel[] = ["High", "Medium", "Low"];
