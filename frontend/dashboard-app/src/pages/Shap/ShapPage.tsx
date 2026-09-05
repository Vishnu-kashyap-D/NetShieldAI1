import { useRef, useState, type FormEvent } from "react";
import { useDataProvider } from "../../data/DataModeContext";
import { ApiUnavailableError } from "../../data/errors";
import type { ChatMessage } from "../../types/api";
import { PageHeader } from "../../components/common/PageHeader";
import { SectionCard } from "../../components/common/SectionCard";
import { IconModelShield, IconSend } from "../../components/common/icons";
import "../../components/alertDetail/ExplainabilityChat.css";

interface DisplayMessage {
  role: "user" | "assistant";
  content: string;
  isError?: boolean;
}

const SUGGESTED_QUESTIONS = [
  "What does this project actually do?",
  "How accurate is the model?",
  "What is a DoS/DDoS attack?",
  "Why is macro F1 so much lower than weighted F1?",
  "What are the project's known limitations?",
];

/**
 * General project/threat Q&A -- NOT grounded in any one alert (contrast with
 * ExplainabilityChat, which only ever discusses one specific alert's own data). Every
 * question goes through DataProvider.askProjectQuestion(), which in real mode calls the
 * backend's Gemini-backed assistant (see backend/app/chat_service.py::answer_project_question)
 * and in mock mode uses a small keyword-matched stand-in (src/data/mock/projectChatEngine.ts).
 * The assistant is instructed server-side to only answer questions about this project or
 * general network-security topics, refusing anything else -- this component just displays
 * whatever it says, it never enforces that scope itself.
 */
export function ShapPage() {
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

    const history: ChatMessage[] = messages.filter((m) => !m.isError).map((m) => ({ role: m.role, content: m.content }));

    setMessages((prev) => [...prev, { role: "user", content: trimmed }]);
    setInput("");
    setPending(true);
    scrollToBottom();

    try {
      const result = await provider.askProjectQuestion(trimmed, history);
      setMessages((prev) => [...prev, { role: "assistant", content: result.answer }]);
    } catch (err) {
      const message =
        err instanceof ApiUnavailableError
          ? `Couldn't reach the assistant: ${err.message}`
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
    <section>
      <PageHeader
        title="SHAP"
        subtitle="Ask about how NetShield AI works, its evaluation results, or general network-security threats"
      />

      <SectionCard
        title={
          <span className="chat-title">
            <IconModelShield />
            Project &amp; threat assistant
          </span>
        }
        subtitle="Answers only questions about this project or general cybersecurity threats -- everything else is politely declined"
        className="explainability-chat"
      >
        {messages.length === 0 ? (
          <div className="chat-empty">
            <div className="chat-empty-title">
              Ask about the detection pipeline, its results and limitations, or a threat type like DoS/DDoS or port scanning.
            </div>
            <div className="chip-row">
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
                {m.role === "assistant" && (
                  <span className="chat-avatar" aria-hidden="true">
                    <IconModelShield />
                  </span>
                )}
                <div className={`chat-bubble chat-bubble--${m.role}${m.isError ? " chat-bubble--error" : ""}`}>
                  <div className="chat-bubble-text">{m.content}</div>
                </div>
              </div>
            ))}
            {pending && (
              <div className="chat-bubble-row chat-bubble-row--assistant">
                <span className="chat-avatar" aria-hidden="true">
                  <IconModelShield />
                </span>
                <div className="chat-bubble chat-bubble--assistant chat-bubble--pending">
                  <span className="visually-hidden">The assistant is composing an answer</span>
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
            placeholder="Ask about the project or a network threat…"
            aria-label="Ask the project assistant"
            disabled={pending}
          />
          <button type="submit" className="btn primary chat-send-btn" disabled={pending || !input.trim()} aria-label="Send question">
            <IconSend />
            <span className="chat-send-label">Send</span>
          </button>
        </form>
      </SectionCard>
    </section>
  );
}
