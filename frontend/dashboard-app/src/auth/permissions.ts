import type { UserRole } from "../types/api";

// Mirrors backend/app/auth.py's permission matrix exactly -- kept in sync by hand (there's no
// shared schema between the two languages). The backend is the actual enforcement; this exists
// so the UI can honestly hide/disable actions a role can't take instead of only failing after
// the fact with a raw 403. If these two ever drift, the backend wins -- a UI that shows an
// action the backend then rejects is a bug in this file, not a security hole (the reverse,
// hiding something the backend would actually allow, is merely an annoyance, not a hole either).
export const CAN_SUBMIT_FEEDBACK: readonly UserRole[] = ["Security Analyst", "Threat Hunter", "Administrator"];
export const CAN_INGEST_TRAFFIC: readonly UserRole[] = ["Threat Hunter", "Administrator"];
export const CAN_TRIGGER_RETRAIN: readonly UserRole[] = ["Administrator"];
export const CAN_MANAGE_USERS: readonly UserRole[] = ["Administrator"];

export function roleCan(role: UserRole | undefined, allowed: readonly UserRole[]): boolean {
  return !!role && allowed.includes(role);
}
