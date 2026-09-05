import type { AlertDetailOut, ChatOut, ChatSources, ShapFeature } from "../../types/api";
import { parseShapFeatures } from "../shap";
import { FEATURE_GLOSSARY, findFeaturesMentioned } from "../featureGlossary";

// TypeScript mirror of backend/app/chat_service.py's deterministic question matching, run
// entirely client-side against this mock alert's own (synthetic) data -- MockDataProvider makes
// no network calls of any kind, so this is the ONLY chat logic mock mode has; there is no LLM
// fallback here, by design (see mockProvider.ts::askAboutAlert). Every answer is grounded in
// this specific alert's fields, exactly like the real backend, and never a single canned string.

const SHAP_DIRECTION_MEANING = {
  classifier:
    "This explains the predicted class's probability, relative to this explanation's background sample. " +
    "Positive means the feature increased that probability; negative means it decreased it -- not automatically " +
    "\"toward BENIGN,\" since it may reflect movement toward any other category. This is an attribution of the " +
    "model's output, not proof of causation.",
  anomaly:
    "This explains the reconstruction-error output, relative to this explanation's background sample. Positive " +
    "means the feature increased that error (more anomalous); negative means it decreased it (more normal-looking). " +
    "This is an attribution of the model's output, not proof of causation.",
};

const GLOSSARY_RE = /\bwhat (?:does|is|are)\b.+\bmean\b|\bdefine\b|\bmeaning of\b/i;
const WHY_CLASSIFIED_RE = /why\s+(?:was|is)\b.*\bclassif|why\s+.*\bclassified as/i;
const WHY_RISK_RE = /why\s+.*\brisk\b|risk\s+(?:score|level)\b/i;
const ANOMALY_CONTRIB_RE = /anomaly\s+detector\s+contribut|how\s+.*\banomaly\b.*\bcontribut/i;
const TOP_OVERALL_RE = /\boverall\b/i;
const TOP_FEATURES_RE =
  /contribut(?:ed|ing)?\s+most|most\s+.*contribut|strongest\s+.*contribut|top\s+contribut|which\s+features?\s+contribut|largest\s+shap|which\s+feature\s+had\s+the\s+largest/i;
const POSITIVE_RE = /increas|toward\s+.*(attack|predicted)|push(?:ed)?\s+toward|\bpositive\b/i;
const NEGATIVE_RE = /decreas|away\s+from|push(?:ed)?\s+away|toward\s+benign|\bbenign\b|\bnegative\b/i;
const CONFIDENCE_RE = /confiden/i;
const ANOMALY_SCORE_RE = /anomaly\s+score|reconstruction\s+error/i;

function fmtPct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function fmtSigned(value: number | undefined): string {
  if (value === undefined) return "sign unavailable";
  return `${value >= 0 ? "+" : ""}${value.toFixed(4)}`;
}

function listFeatures(entries: ShapFeature[], limit: number): string {
  return entries
    .slice(0, limit)
    .map((e) => `- ${e.feature}: ${fmtSigned(e.shap_value)} (mean |SHAP| ${e.mean_abs_shap.toFixed(4)})`)
    .join("\n");
}

function shapUnavailableReason(alert: AlertDetailOut): string {
  if (alert.risk_level === "Low") {
    return "SHAP explanations are only generated for Medium/High risk alerts, and this window was scored Low risk.";
  }
  if (!alert.is_anomaly) {
    return "this window never reached the classifier -- the anomaly gate didn't flag it, so nothing was classified or explained.";
  }
  return "this alert wasn't scored with SHAP explanations enabled at ingest time.";
}

interface Answer {
  text: string;
  sources: ChatSources;
}

function noSources(): ChatSources {
  return { prediction: false, shap: false, feature_values: false, glossary: false };
}

function answerDeterministic(question: string, alert: AlertDetailOut): Answer | null {
  const classifierShap = parseShapFeatures(alert.top_classifier_features).slice().sort((a, b) => b.mean_abs_shap - a.mean_abs_shap);
  const anomalyShap = parseShapFeatures(alert.top_anomaly_features).slice().sort((a, b) => b.mean_abs_shap - a.mean_abs_shap);
  const hasFeatureValues = Object.keys(alert.features ?? {}).length > 0;

  if (GLOSSARY_RE.test(question)) {
    const mentioned = findFeaturesMentioned(question).filter((name) => name in FEATURE_GLOSSARY);
    if (mentioned.length === 0) {
      return {
        text: "I don't have a definition for that in the project's CICIDS2017 feature glossary.",
        sources: { ...noSources(), glossary: true },
      };
    }
    const lines = mentioned.map((name) => `**${name}**: ${FEATURE_GLOSSARY[name]}`);
    let usedShap = false;
    for (const name of mentioned) {
      const hit = [...classifierShap, ...anomalyShap].find((e) => e.feature === name);
      if (hit) {
        usedShap = true;
        lines.push(`\nFor this alert, ${name} had a SHAP value of ${fmtSigned(hit.shap_value)} (direction: ${hit.direction ?? "unknown"}).`);
      }
    }
    return { text: lines.join("\n"), sources: { prediction: false, shap: usedShap, feature_values: false, glossary: true } };
  }

  if (WHY_CLASSIFIED_RE.test(question)) {
    if (!alert.is_anomaly) {
      return {
        text:
          `This window was predicted as ${alert.predicted_label}. It never reached the classifier at all: the ` +
          `anomaly score (${alert.anomaly_score.toFixed(4)}) did not exceed the anomaly threshold ` +
          `(${alert.anomaly_threshold.toFixed(4)}), so the anomaly gate did not flag it for classification.`,
        sources: { ...noSources(), prediction: true },
      };
    }
    if (classifierShap.length === 0) {
      return {
        text:
          `This traffic was classified as ${alert.predicted_label} with ${fmtPct(alert.confidence)} confidence. ` +
          `I can't reliably explain which features drove that prediction, though: ${shapUnavailableReason(alert)}`,
        sources: { ...noSources(), prediction: true },
      };
    }
    return {
      text:
        `This traffic was classified as ${alert.predicted_label} with ${fmtPct(alert.confidence)} confidence.\n\n` +
        `The strongest features contributing to the prediction were:\n${listFeatures(classifierShap, 5)}\n\n` +
        SHAP_DIRECTION_MEANING.classifier,
      sources: { prediction: true, shap: true, feature_values: hasFeatureValues, glossary: false },
    };
  }

  if (WHY_RISK_RE.test(question)) {
    const text =
      `This alert is ${alert.risk_level} risk, with a fused risk score of ${alert.risk_score.toFixed(4)}.\n\n` +
      `NetShield's hybrid risk score is the higher of the normalized anomaly score and (if the window reached ` +
      `the classifier) the classifier's confidence -- so a confident attack classification is never reported as ` +
      `less risky than the anomaly detector alone already thought.\n\n` +
      `Raw anomaly score: ${alert.anomaly_score.toFixed(4)} (threshold ${alert.anomaly_threshold.toFixed(4)})\n` +
      (alert.is_anomaly
        ? `Classifier confidence: ${fmtPct(alert.confidence)}\n`
        : "Classifier confidence: n/a (window never reached the classifier)\n") +
      `\nThe risk level bucket (${alert.risk_level}) comes from comparing that fused score against calibrated Low/Medium/High cutoffs.`;
    return { text, sources: { ...noSources(), prediction: true } };
  }

  if (ANOMALY_CONTRIB_RE.test(question)) {
    let text =
      `The Autoencoder (anomaly detector) scored this window's reconstruction error at ${alert.anomaly_score.toFixed(4)} ` +
      `against a calibrated threshold of ${alert.anomaly_threshold.toFixed(4)} -- ` +
      `${alert.is_anomaly ? "above" : "not above"} the threshold, so this window ${alert.is_anomaly ? "was" : "was not"} ` +
      `flagged as anomalous${alert.is_anomaly ? " and passed on to the classifier." : ", so it never reached the classifier."}`;
    if (anomalyShap.length > 0) {
      text += `\n\nFeatures that most influenced the anomaly score:\n${listFeatures(anomalyShap, 5)}\n\n${SHAP_DIRECTION_MEANING.anomaly}`;
      return { text, sources: { prediction: true, shap: true, feature_values: hasFeatureValues, glossary: false } };
    }
    text += `\n\nI can't break that down by feature, though: ${shapUnavailableReason(alert)}`;
    return { text, sources: { ...noSources(), prediction: true } };
  }

  if (TOP_OVERALL_RE.test(question)) {
    const merged = [...classifierShap, ...anomalyShap].sort((a, b) => b.mean_abs_shap - a.mean_abs_shap);
    if (merged.length === 0) {
      return { text: `No SHAP explanation is available for this alert: ${shapUnavailableReason(alert)}`, sources: { ...noSources(), prediction: true } };
    }
    return {
      text: `Across both the classifier and anomaly explanations, the most important features overall were:\n${listFeatures(merged, 6)}`,
      sources: { prediction: true, shap: true, feature_values: hasFeatureValues, glossary: false },
    };
  }

  if (TOP_FEATURES_RE.test(question)) {
    if (classifierShap.length === 0) {
      return { text: `No classifier SHAP explanation is available for this alert: ${shapUnavailableReason(alert)}`, sources: { ...noSources(), prediction: true } };
    }
    return {
      text: `The features that contributed most to the prediction (${alert.predicted_label}) were:\n${listFeatures(classifierShap, 5)}`,
      sources: { prediction: true, shap: true, feature_values: hasFeatureValues, glossary: false },
    };
  }

  if (POSITIVE_RE.test(question)) {
    if (classifierShap.length === 0) {
      return { text: `No classifier SHAP explanation is available for this alert: ${shapUnavailableReason(alert)}`, sources: { ...noSources(), prediction: true } };
    }
    const positives = classifierShap.filter((e) => e.direction === "positive");
    if (positives.length === 0) {
      return { text: "None of this alert's top SHAP features had a positive (toward the predicted class) contribution.", sources: { prediction: true, shap: true, feature_values: false, glossary: false } };
    }
    return {
      text: `These features pushed toward the predicted class (${alert.predicted_label}):\n${listFeatures(positives, 5)}\n\n${SHAP_DIRECTION_MEANING.classifier}`,
      sources: { prediction: true, shap: true, feature_values: hasFeatureValues, glossary: false },
    };
  }

  if (NEGATIVE_RE.test(question)) {
    if (classifierShap.length === 0) {
      return { text: `No classifier SHAP explanation is available for this alert: ${shapUnavailableReason(alert)}`, sources: { ...noSources(), prediction: true } };
    }
    const negatives = classifierShap.filter((e) => e.direction === "negative");
    if (negatives.length === 0) {
      return { text: "None of this alert's top SHAP features had a negative (away from the predicted class) contribution.", sources: { prediction: true, shap: true, feature_values: false, glossary: false } };
    }
    return {
      text: `These features pushed away from the predicted class (${alert.predicted_label}):\n${listFeatures(negatives, 5)}\n\n${SHAP_DIRECTION_MEANING.classifier}`,
      sources: { prediction: true, shap: true, feature_values: hasFeatureValues, glossary: false },
    };
  }

  if (CONFIDENCE_RE.test(question)) {
    if (!alert.is_anomaly) {
      return {
        text: "There is no classifier confidence for this window -- it never reached the classifier because the anomaly gate didn't flag it as anomalous.",
        sources: { ...noSources(), prediction: true },
      };
    }
    return {
      text: `The BiLSTM classifier's confidence in its predicted class (${alert.predicted_label}) was ${fmtPct(alert.confidence)}.`,
      sources: { ...noSources(), prediction: true },
    };
  }

  if (ANOMALY_SCORE_RE.test(question)) {
    return {
      text:
        `The Autoencoder's reconstruction-error (anomaly) score for this window was ${alert.anomaly_score.toFixed(4)}, ` +
        `against a calibrated threshold of ${alert.anomaly_threshold.toFixed(4)} (${alert.is_anomaly ? "above" : "not above"} threshold).`,
      sources: { ...noSources(), prediction: true },
    };
  }

  return null;
}

/**
 * Open-ended fallback for mock mode -- there is no LLM here (mock mode must work without an
 * API key), so this is a data-driven template, not a free-form generator. It still varies by
 * alert (predicted label, confidence, top features) rather than returning one fixed string.
 */
function answerOpenEnded(alert: AlertDetailOut): Answer {
  const classifierShap = parseShapFeatures(alert.top_classifier_features).slice().sort((a, b) => b.mean_abs_shap - a.mean_abs_shap);
  if (!alert.is_anomaly) {
    return {
      text:
        `In plain terms: this traffic window looked normal enough that the anomaly detector never flagged it, so it ` +
        `was never sent to the classifier and is reported as ${alert.predicted_label} (risk: ${alert.risk_level}).`,
      sources: { ...noSources(), prediction: true },
    };
  }
  const topLine = classifierShap.length > 0 ? ` The biggest driver was ${classifierShap[0].feature}.` : "";
  return {
    text:
      `In plain terms: NetShield's anomaly detector flagged this window (score ${alert.anomaly_score.toFixed(4)} vs. ` +
      `threshold ${alert.anomaly_threshold.toFixed(4)}), and the classifier then labeled it ${alert.predicted_label} ` +
      `with ${fmtPct(alert.confidence)} confidence, giving it a ${alert.risk_level} risk rating.${topLine}\n\n` +
      "(Demo data -- generated locally, not live model output. Ask about a specific number -- confidence, " +
      "anomaly score, risk, or top features -- for a more precise, data-grounded answer.)",
    sources: {
      prediction: true,
      shap: classifierShap.length > 0,
      feature_values: Object.keys(alert.features ?? {}).length > 0,
      glossary: false,
    },
  };
}

export function mockChatAnswer(question: string, alert: AlertDetailOut): ChatOut {
  const deterministic = answerDeterministic(question, alert);
  const answer = deterministic ?? answerOpenEnded(alert);
  return { answer: answer.text, sources: answer.sources };
}
