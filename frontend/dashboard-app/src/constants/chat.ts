/**
 * Chat input limits. The backend is the real enforcement (backend/app/schemas.py's CHAT_* values,
 * plus a per-user request rate limit) -- these exist so the UI never lets someone compose a
 * message the API is already known to reject, and never sends a conversation the API would refuse.
 * Keep them in step with the backend.
 */

/** Max characters in one question. Mirrors CHAT_QUESTION_MAX_CHARS. */
export const CHAT_QUESTION_MAX_CHARS = 2000;

/**
 * Prior turns sent along with each question. The backend accepts up to 40 (CHAT_HISTORY_MAX_TURNS);
 * this stays well under that so a long-running conversation keeps working instead of eventually
 * tripping the limit -- only the most recent turns matter for the LLM's multi-turn context anyway.
 */
export const CHAT_HISTORY_MAX_TURNS = 20;
