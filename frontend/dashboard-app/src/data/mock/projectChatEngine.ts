import type { ChatOut } from "../../types/api";

// Mock-mode counterpart to backend/app/chat_service.py::answer_project_question. Mock mode makes
// no network/LLM calls of any kind (see chatEngine.ts's own note on the per-alert mock chat), so
// this is a small, honest, keyword-matched stand-in -- not a real Gemini call, and not pretending
// to be one. Topic scope mirrors the real assistant's system prompt: this project, or general
// network-threat concepts; anything else gets the same one-sentence redirect the real backend gives.

const PROJECT_RE =
  /\b(netshield|pipeline|architecture|autoencoder|bilstm|cicids|dataset|accura|precision|recall|\bf1\b|macro|weighted|risk fusion|shap|explainab|feature|backend|frontend|\bstack\b|limitation|metric|evaluat|the model\b|this project\b|how (does|is) (it|this|netshield)|what does (it|this|netshield) do)/i;
const THREAT_RE = /\b(dos|ddos|denial of service|brute.?force|port.?scan|malware|botnet|\bbot\b|exfiltrat|phishing|intrusion|attack|threat|cyber|network security|firewall|zero.day)/i;

const PROJECT_SUMMARY =
  "NetShield AI is a hybrid intrusion detection system: an Autoencoder (trained on benign " +
  "traffic only) gates which windows reach a BiLSTM classifier, which sorts flagged traffic into " +
  "six categories (DoS/DDoS, Brute Force, Port Scanning, Malware Traffic, Botnet Activity, Data " +
  "Exfiltration). A Hybrid Risk Fusion step combines both models' signals into a Low/Medium/High " +
  "risk level, and SHAP explains Medium/High alerts. On the held-out CICIDS2017 test set, the " +
  "classifier reaches 96.1% accuracy and 97.2% weighted F1, but only 54.4% macro F1 -- the " +
  "well-represented categories (DoS/DDoS, Port Scanning) score near-perfectly, while data-scarce " +
  "categories (Botnet Activity, Malware Traffic, Data Exfiltration) score much lower purely from " +
  "having too few labeled samples, not a modeling flaw.";

const OFF_TOPIC_REPLY =
  "I can only help with questions about the NetShield AI project or general network-security " +
  "threats -- try asking about the detection pipeline, its evaluation results, or a threat type " +
  "like DoS/DDoS or port scanning.";

const UNAVAILABLE_NOTE =
  "\n\n(Demo stream: this is a canned, keyword-matched response, not a live Gemini call -- switch " +
  "to Live API mode to reach the real assistant.)";

export function mockProjectChatAnswer(question: string): ChatOut {
  const onTopic = PROJECT_RE.test(question) || THREAT_RE.test(question);
  const answer = onTopic ? `${PROJECT_SUMMARY}${UNAVAILABLE_NOTE}` : `${OFF_TOPIC_REPLY}${UNAVAILABLE_NOTE}`;
  return { answer, sources: { prediction: false, shap: false, feature_values: false, glossary: false } };
}
