import type { ChatMessage } from "../types/api";
import { CHAT_HISTORY_MAX_TURNS } from "../constants/chat";

/**
 * Turns a chat panel's displayed messages into the `history` sent with the next question.
 *
 * Drops error bubbles (not part of the conversation), keeps only the most recent
 * CHAT_HISTORY_MAX_TURNS turns so a long conversation never exceeds what the API accepts, and
 * then drops any *leading* assistant turns: after trimming, the window can start mid-exchange, and
 * an LLM conversation that opens with the model's own reply (no user turn before it) is malformed
 * for some providers, so the history must begin with a user turn.
 */
export function toRequestHistory(messages: { role: "user" | "assistant"; content: string; isError?: boolean }[]): ChatMessage[] {
  const recent = messages
    .filter((m) => !m.isError)
    .map((m) => ({ role: m.role, content: m.content }))
    .slice(-CHAT_HISTORY_MAX_TURNS);
  const firstUser = recent.findIndex((m) => m.role === "user");
  return firstUser === -1 ? [] : recent.slice(firstUser);
}
