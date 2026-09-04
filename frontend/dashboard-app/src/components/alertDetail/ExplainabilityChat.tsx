import { useRef, useState, type FormEvent } from "react";
import type { AlertDetailOut, ChatMessage, ChatSources } from "../../types/api";
import { useDataProvider } from "../../data/DataModeContext";
import { ApiUnavailableError, NotFoundError } from "../../data/errors";
import { SectionCard } from "../common/SectionCard";
import "./ExplainabilityChat.css";

interface DisplayMessage {
  role: "user" | "assistant";
  content: string;
  sources?: ChatSources;
  isError?: boolean;
}

const SUGGESTED_QUESTIONS = [
  "Why was this classified this way?",
  "Which features contributed most?",
  "Why is the risk high?",
  "Which features pushed away from the attack?",
  "How confident was the model?",
];

const SOURCE_LABELS: Record<keyof ChatSources, string> = {
  prediction: "Prediction",
  shap: "SHAP",
  feature_values: "Feature values",
  glossary: "Glossary",
};

function SourceTags({ sources }: { sources: ChatSources }) {
  const active = (Object.keys(sources) as (keyof ChatSources)[]).filter((key) => sources[key]);
  if (active.length === 0) return null;
  return (
    <div className="chat-sources">
      <span className="chat-sources-label">Grounded in:</span>
      {active.map((key) => (
        <span key={key} className="chat-source-tag">
          {SOURCE_LABELS[key]}
        </span>
      ))}
    </div>
  );
}

/**
 * Explainability chatbot for one specific alert (backend/app/routers/chat.py::chat_about_alert,
 * or MockDataProvider's deterministic chat engine in mock mode). Every question/answer round
 * trip goes through DataProvider.askAboutAlert() -- this component never calls an LLM or the
 * backend directly, and never invents an answer of its own when a request fails.
 */
export function ExplainabilityChat({ alert }: { alert: AlertDetailOut }) {
  const provider = useDataProvider();
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [input, setInput] = useState("");
  const [pending, setPending] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  function scrollToBottom() {
    requestAnimationFrame(() => {
      listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: "smooth" });
    });
  }

  async function send(question: string) {
    const trimmed = question.trim();
    if (!trimmed || pending) return;

    const history: ChatMessage[] = messages
      .filter((m) => !m.isError)
      .map((m) => ({ role: m.role, content: m.content }));

    setMessages((prev) => [...prev, { role: "user", content: trimmed }]);
    setInput("");
    setPending(true);
    scrollToBottom();

    try {
      const result = await provider.askAboutAlert(alert.id, trimmed, history);
      setMessages((prev) => [...prev, { role: "assistant", content: result.answer, sources: result.sources }]);
    } catch (err) {
      const message =
        err instanceof NotFoundError
          ? "This alert could not be found -- it may have been from a different session or data mode."
          : err instanceof ApiUnavailableError
            ? `Couldn't reach the explainability service: ${err.message}`
            : err instanceof Error
              ? `Couldn't get an answer: ${err.message}`
              : "Couldn't get an answer.";
      setMessages((prev) => [...prev, { role: "assistant", content: message, isError: true }]);
    } finally {
      setPending(false);
      scrollToBottom();
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    void send(input);
  }

  return (
    <SectionCard
      title="Ask about this prediction"
      subtitle="Grounded in this alert's own prediction and SHAP data -- it never invents an explanation the data doesn't support"
      className="explainability-chat"
    >
      {messages.length === 0 ? (
        <div className="chat-empty">
          <div className="chat-empty-title">Ask me anything about why NetShield made this prediction.</div>
          <div className="chat-suggestions">
            {SUGGESTED_QUESTIONS.map((q) => (
              <button key={q} type="button" className="chat-suggestion-chip" onClick={() => void send(q)} disabled={pending}>
                {q}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="chat-messages" ref={listRef} role="log" aria-live="polite">
          {messages.map((m, i) => (
            <div key={i} className={`chat-bubble-row chat-bubble-row--${m.role}`}>
              <div className={`chat-bubble chat-bubble--${m.role}${m.isError ? " chat-bubble--error" : ""}`}>
                <div className="chat-bubble-author">{m.role === "user" ? "You" : "NetShield Explainability"}</div>
                <div className="chat-bubble-text">{m.content}</div>
                {m.sources && <SourceTags sources={m.sources} />}
              </div>
            </div>
          ))}
          {pending && (
            <div className="chat-bubble-row chat-bubble-row--assistant">
              <div className="chat-bubble chat-bubble--assistant chat-bubble--pending">
                <div className="chat-bubble-author">NetShield Explainability</div>
                <div className="chat-typing">
                  <span />
                  <span />
                  <span />
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      <form className="chat-input-row" onSubmit={handleSubmit}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Type your question…"
          aria-label="Ask about this prediction"
          disabled={pending}
        />
        <button type="submit" className="btn primary" disabled={pending || !input.trim()}>
          Send
        </button>
      </form>
    </SectionCard>
  );
}
