from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from cyber_ai.explain import SHAP_DIRECTION_MEANING

from app.config import settings
from app.feature_glossary import find_features_mentioned, get_definitions
from app.models import Alert

logger = logging.getLogger("netshield.backend")


class LlmUnavailableError(Exception):
    """The LLM explanation layer could not be reached or is not configured."""


@dataclass
class ChatSources:
    prediction: bool = False
    shap: bool = False
    feature_values: bool = False
    glossary: bool = False

    def as_dict(self) -> dict[str, bool]:
        return {
            "prediction": self.prediction,
            "shap": self.shap,
            "feature_values": self.feature_values,
            "glossary": self.glossary,
        }


@dataclass
class ChatAnswer:
    text: str
    sources: ChatSources = field(default_factory=ChatSources)


def parse_shap_json(raw: str | None) -> list[dict]:
    """Parses a stored top_classifier_features/top_anomaly_features JSON string.

    Tolerant of the pre-sign-fix shape (cyber_ai/explain.py before this change stored only
    {feature, mean_abs_shap}) -- any alert row written before this feature shipped will have
    shap_value/direction missing rather than absent entirely. Those fields come back as None /
    "unknown" so callers can state "direction unknown" instead of guessing or crashing.
    """
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []

    entries: list[dict] = []
    for entry in parsed:
        if not isinstance(entry, dict) or "feature" not in entry or "mean_abs_shap" not in entry:
            continue
        entries.append(
            {
                "feature": entry["feature"],
                "shap_value": entry.get("shap_value"),
                "mean_abs_shap": entry["mean_abs_shap"],
                "direction": entry.get("direction", "unknown"),
            }
        )
    return entries


def build_alert_context(alert: Alert) -> dict:
    """Assembles the ONLY data the chatbot (deterministic or LLM) is allowed to reason from.

    Deliberately excludes: model files, preprocessing artifacts, database credentials, and
    any alert other than this one -- the chatbot never queries the database or filesystem
    itself, it only receives this pre-built, already-fetched context dict.
    """
    classifier_shap = parse_shap_json(alert.top_classifier_features)
    anomaly_shap = parse_shap_json(alert.top_anomaly_features)

    named_features = sorted({entry["feature"] for entry in classifier_shap} | {entry["feature"] for entry in anomaly_shap})
    features = alert.features or {}
    relevant_feature_values = {name: features.get(name) for name in named_features if name in features}

    return {
        "alert_id": alert.id,
        "predicted_label": alert.predicted_label,
        "actual_label": alert.actual_label,
        "actual_category": alert.actual_category,
        "confidence": alert.confidence,
        "is_anomaly": alert.is_anomaly,
        "pipeline_action": alert.pipeline_action,
        "anomaly_score": alert.anomaly_score,
        "anomaly_threshold": alert.anomaly_threshold,
        "risk_score": alert.risk_score,
        "risk_level": alert.risk_level,
        "classifier_shap": classifier_shap,
        "anomaly_shap": anomaly_shap,
        "relevant_feature_values": relevant_feature_values,
        "feature_glossary": get_definitions(named_features),
        "shap_direction_meaning": SHAP_DIRECTION_MEANING,
    }


# ---------------------------------------------------------------------------
# Deterministic question handling -- answered directly from structured data,
# with no LLM call, whenever the question matches a known intent. This keeps
# the most common questions fast, free, and impossible to hallucinate; only
# genuinely open-ended questions fall through to the LLM (see answer_with_llm).
# ---------------------------------------------------------------------------

_GLOSSARY_PATTERN = re.compile(r"\bwhat (?:does|is|are)\b.+\bmean\b|\bdefine\b|\bmeaning of\b", re.IGNORECASE)
_WHY_CLASSIFIED_PATTERN = re.compile(r"why\s+(?:was|is)\b.*\bclassif|why\s+.*\bclassified as", re.IGNORECASE)
_WHY_RISK_PATTERN = re.compile(r"why\s+.*\brisk\b|risk\s+(?:score|level)\b", re.IGNORECASE)
_ANOMALY_CONTRIB_PATTERN = re.compile(r"anomaly\s+detector\s+contribut|how\s+.*\banomaly\b.*\bcontribut", re.IGNORECASE)
_TOP_OVERALL_PATTERN = re.compile(r"\boverall\b|most important features?\b(?!.*prediction)", re.IGNORECASE)
_TOP_FEATURES_PATTERN = re.compile(
    r"contribut(?:ed|ing)?\s+most|most\s+.*contribut|strongest\s+.*contribut|top\s+contribut|"
    r"which\s+features?\s+contribut|largest\s+shap|which\s+feature\s+had\s+the\s+largest",
    re.IGNORECASE,
)
_POSITIVE_PATTERN = re.compile(r"increas|toward\s+.*(attack|predicted)|push(?:ed)?\s+toward|\bpositive\b", re.IGNORECASE)
_NEGATIVE_PATTERN = re.compile(r"decreas|away\s+from|push(?:ed)?\s+away|toward\s+benign|\bbenign\b|\bnegative\b", re.IGNORECASE)
_CONFIDENCE_PATTERN = re.compile(r"confiden", re.IGNORECASE)
_ANOMALY_SCORE_PATTERN = re.compile(r"anomaly\s+score|reconstruction\s+error", re.IGNORECASE)


def _fmt_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _fmt_signed(value: float | None) -> str:
    if value is None:
        return "sign unavailable"
    return f"{value:+.4f}"


def _shap_unavailable_reason(context: dict) -> str:
    if context["risk_level"] == "Low":
        return "SHAP explanations are only generated for Medium/High risk alerts, and this window was scored Low risk."
    if not context["is_anomaly"]:
        return "this window never reached the classifier -- the anomaly gate didn't flag it, so nothing was classified or explained."
    return (
        "this alert wasn't scored with SHAP explanations enabled at ingest time (or its batch had "
        "more Medium/High alerts than the SHAP explanation cap for that ingest call)."
    )


def _list_features(entries: list[dict], limit: int) -> str:
    lines = []
    for entry in entries[:limit]:
        lines.append(f"- {entry['feature']}: {_fmt_signed(entry['shap_value'])} (mean |SHAP| {entry['mean_abs_shap']:.4f})")
    return "\n".join(lines)


def try_deterministic_answer(question: str, context: dict) -> ChatAnswer | None:
    classifier_shap: list[dict] = context["classifier_shap"]
    anomaly_shap: list[dict] = context["anomaly_shap"]

    # "What does <feature> mean?" -- static glossary lookup, optionally enriched with this
    # alert's own SHAP value for that feature if it happens to be one of the top ones.
    if _GLOSSARY_PATTERN.search(question):
        mentioned = find_features_mentioned(question)
        known = [name for name in mentioned if name in context["feature_glossary"]]
        if known:
            lines = [f"**{name}**: {context['feature_glossary'][name]}" for name in known]
            for name in known:
                for entry in classifier_shap + anomaly_shap:
                    if entry["feature"] == name:
                        lines.append(
                            f"\nFor this alert, {name} had a SHAP value of {_fmt_signed(entry['shap_value'])} "
                            f"(direction: {entry['direction']})."
                        )
                        break
            return ChatAnswer("\n".join(lines), ChatSources(prediction=False, shap=bool(known and (classifier_shap or anomaly_shap)), feature_values=False, glossary=True))
        return ChatAnswer(
            "I don't have a definition for that in the project's CICIDS2017 feature glossary.",
            ChatSources(glossary=True),
        )

    # "Why was this classified as X?"
    if _WHY_CLASSIFIED_PATTERN.search(question):
        if not context["is_anomaly"]:
            return ChatAnswer(
                f"This window was predicted as {context['predicted_label']}. It never reached the classifier at all: "
                f"the anomaly score ({context['anomaly_score']:.4f}) did not exceed the anomaly threshold "
                f"({context['anomaly_threshold']:.4f}), so the anomaly gate did not flag it for classification.",
                ChatSources(prediction=True),
            )
        if not classifier_shap:
            return ChatAnswer(
                f"This traffic was classified as {context['predicted_label']} with {_fmt_pct(context['confidence'])} "
                f"confidence. I can't reliably explain which features drove that prediction, though: "
                f"{_shap_unavailable_reason(context)}",
                ChatSources(prediction=True, shap=False),
            )
        top = sorted(classifier_shap, key=lambda e: e["mean_abs_shap"], reverse=True)
        answer = (
            f"This traffic was classified as {context['predicted_label']} with {_fmt_pct(context['confidence'])} confidence.\n\n"
            f"The strongest features contributing to the prediction were:\n{_list_features(top, 5)}\n\n"
            f"{SHAP_DIRECTION_MEANING['classifier']}"
        )
        return ChatAnswer(answer, ChatSources(prediction=True, shap=True, feature_values=bool(context["relevant_feature_values"])))

    # "Why is this alert high/medium/low risk?" / "what is the risk score/level"
    if _WHY_RISK_PATTERN.search(question):
        answer = (
            f"This alert is {context['risk_level']} risk, with a fused risk score of {context['risk_score']:.4f}.\n\n"
            f"NetShield's hybrid risk score is the higher of the normalized anomaly score and (if the window reached "
            f"the classifier) the classifier's confidence -- so a confident attack classification is never reported "
            f"as less risky than the anomaly detector alone already thought. (The normalized anomaly score itself "
            f"isn't stored on the alert, only the raw values below, so I can't tell you the exact normalized number "
            f"that fed into the fusion -- only which raw signals were involved.)\n\n"
            f"Raw anomaly score: {context['anomaly_score']:.4f} (threshold {context['anomaly_threshold']:.4f})\n"
            + (f"Classifier confidence: {_fmt_pct(context['confidence'])}\n" if context["is_anomaly"] else "Classifier confidence: n/a (window never reached the classifier)\n")
            + f"\nThe risk level bucket ({context['risk_level']}) comes from comparing that fused score against "
            f"calibrated Low/Medium/High cutoffs."
        )
        return ChatAnswer(answer, ChatSources(prediction=True))

    # "How did the anomaly detector contribute to this alert?"
    if _ANOMALY_CONTRIB_PATTERN.search(question):
        base = (
            f"The Autoencoder (anomaly detector) scored this window's reconstruction error at "
            f"{context['anomaly_score']:.4f} against a calibrated threshold of {context['anomaly_threshold']:.4f} -- "
            f"{'above' if context['is_anomaly'] else 'not above'} the threshold, so this window "
            f"{'was' if context['is_anomaly'] else 'was not'} flagged as anomalous"
            f"{' and passed on to the classifier.' if context['is_anomaly'] else ', so it never reached the classifier.'}"
        )
        if anomaly_shap:
            top = sorted(anomaly_shap, key=lambda e: e["mean_abs_shap"], reverse=True)
            base += f"\n\nFeatures that most influenced the anomaly score:\n{_list_features(top, 5)}\n\n{SHAP_DIRECTION_MEANING['anomaly']}"
            return ChatAnswer(base, ChatSources(prediction=True, shap=True, feature_values=bool(context["relevant_feature_values"])))
        base += f"\n\nI can't break that down by feature, though: {_shap_unavailable_reason(context)}"
        return ChatAnswer(base, ChatSources(prediction=True, shap=False))

    # "Which features contributed most / which feature had the largest SHAP contribution"
    # (interpreted as the classifier's explanation of the prediction, matching how these
    # questions are phrased in the product spec's example UX) and the "...overall" variant,
    # which merges both explainers.
    if _TOP_OVERALL_PATTERN.search(question):
        merged = sorted(classifier_shap + anomaly_shap, key=lambda e: e["mean_abs_shap"], reverse=True)
        if not merged:
            return ChatAnswer(
                f"No SHAP explanation is available for this alert: {_shap_unavailable_reason(context)}",
                ChatSources(prediction=True, shap=False),
            )
        return ChatAnswer(
            f"Across both the classifier and anomaly explanations, the most important features overall were:\n"
            f"{_list_features(merged, 6)}",
            ChatSources(prediction=True, shap=True, feature_values=bool(context["relevant_feature_values"])),
        )

    if _TOP_FEATURES_PATTERN.search(question):
        if not classifier_shap:
            return ChatAnswer(
                f"No classifier SHAP explanation is available for this alert: {_shap_unavailable_reason(context)}",
                ChatSources(prediction=True, shap=False),
            )
        top = sorted(classifier_shap, key=lambda e: e["mean_abs_shap"], reverse=True)
        return ChatAnswer(
            f"The features that contributed most to the prediction ({context['predicted_label']}) were:\n{_list_features(top, 5)}",
            ChatSources(prediction=True, shap=True, feature_values=bool(context["relevant_feature_values"])),
        )

    # "Which features increased the likelihood of the attack / increased the risk?"
    if _POSITIVE_PATTERN.search(question):
        positives = sorted(
            [e for e in classifier_shap if e["direction"] == "positive"], key=lambda e: e["mean_abs_shap"], reverse=True
        )
        if not classifier_shap:
            return ChatAnswer(
                f"No classifier SHAP explanation is available for this alert: {_shap_unavailable_reason(context)}",
                ChatSources(prediction=True, shap=False),
            )
        if not positives:
            return ChatAnswer(
                "None of this alert's top SHAP features had a positive (toward the predicted class) contribution.",
                ChatSources(prediction=True, shap=True),
            )
        return ChatAnswer(
            f"These features pushed toward the predicted class ({context['predicted_label']}):\n{_list_features(positives, 5)}\n\n"
            f"{SHAP_DIRECTION_MEANING['classifier']}",
            ChatSources(prediction=True, shap=True, feature_values=bool(context["relevant_feature_values"])),
        )

    # "Which features pushed the prediction away from the attack / toward benign?"
    if _NEGATIVE_PATTERN.search(question):
        negatives = sorted(
            [e for e in classifier_shap if e["direction"] == "negative"], key=lambda e: e["mean_abs_shap"], reverse=True
        )
        if not classifier_shap:
            return ChatAnswer(
                f"No classifier SHAP explanation is available for this alert: {_shap_unavailable_reason(context)}",
                ChatSources(prediction=True, shap=False),
            )
        if not negatives:
            return ChatAnswer(
                "None of this alert's top SHAP features had a negative (away from the predicted class) contribution.",
                ChatSources(prediction=True, shap=True),
            )
        return ChatAnswer(
            f"These features pushed away from the predicted class ({context['predicted_label']}):\n{_list_features(negatives, 5)}\n\n"
            f"{SHAP_DIRECTION_MEANING['classifier']}",
            ChatSources(prediction=True, shap=True, feature_values=bool(context["relevant_feature_values"])),
        )

    # "What was the model's confidence?"
    if _CONFIDENCE_PATTERN.search(question):
        if not context["is_anomaly"]:
            return ChatAnswer(
                "There is no classifier confidence for this window -- it never reached the classifier because the "
                "anomaly gate didn't flag it as anomalous.",
                ChatSources(prediction=True),
            )
        return ChatAnswer(
            f"The BiLSTM classifier's confidence in its predicted class ({context['predicted_label']}) was "
            f"{_fmt_pct(context['confidence'])}.",
            ChatSources(prediction=True),
        )

    # "What is the anomaly score?"
    if _ANOMALY_SCORE_PATTERN.search(question):
        return ChatAnswer(
            f"The Autoencoder's reconstruction-error (anomaly) score for this window was {context['anomaly_score']:.4f}, "
            f"against a calibrated threshold of {context['anomaly_threshold']:.4f} "
            f"({'above' if context['is_anomaly'] else 'not above'} threshold).",
            ChatSources(prediction=True),
        )

    return None


# ---------------------------------------------------------------------------
# LLM fallback -- only for questions the deterministic matcher above doesn't
# recognize (open-ended synthesis, e.g. "explain this simply"). The LLM never
# sees anything beyond the same structured context dict built above.
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are NetShield AI's Explainability Assistant. You explain ONE specific \
network-intrusion-detection alert to a security analyst, using ONLY the structured JSON context \
supplied to you in this message. You are not the detection model -- you do not see raw network \
traffic, you do not run inference, and you cannot make a new prediction.

Rules you must follow:
- Only use facts present in the supplied context. Never invent a SHAP value, a feature value, a \
confidence number, or any other figure that is not literally in the context.
- Never claim a feature contributed positively or negatively unless the context's classifier_shap \
or anomaly_shap arrays say so via their "direction" field. If "direction" is "unknown" for a \
feature, say the direction isn't available rather than guessing.
- The "shap_direction_meaning" field in the context is the ONLY authoritative interpretation of \
what a positive/negative SHAP value means for each explainer (classifier vs anomaly). Use that \
wording; do not invent your own interpretation, and in particular do not claim a negative \
classifier SHAP value means "toward BENIGN" -- it only means "away from the predicted class."
- If the context's classifier_shap or anomaly_shap list is empty, say explanations aren't \
available for that part rather than fabricating one.
- If the question asks something the context does not cover, say so plainly instead of guessing.
- Do not pretend to have access to the underlying .keras model files, the training data, or any \
alert other than the one described in the context.
- Explain technical terms in plain language where you can, using the feature_glossary entries \
provided -- do not invent feature definitions that are not in feature_glossary.
- Clearly distinguish between model evidence (SHAP values, scores, confidence) and general \
feature definitions (the glossary) -- they answer different kinds of questions.
- Keep answers concise and analyst-facing: a few sentences or a short bulleted list, not an essay.
"""


def _format_context_for_prompt(context: dict) -> str:
    # json.dumps, not an ad-hoc string template -- the model reads this as structured data, and
    # this is the exact same context dict try_deterministic_answer() reasons over, so the LLM
    # path and the deterministic path are always grounded in identical information.
    return json.dumps(context, indent=2, default=str)


def answer_with_llm(question: str, context: dict, history: list[dict] | None = None) -> ChatAnswer:
    if not settings.anthropic_api_key:
        raise LlmUnavailableError("No LLM API key is configured on the server (ANTHROPIC_API_KEY).")

    try:
        import anthropic
    except ImportError as exc:
        raise LlmUnavailableError("The 'anthropic' package is not installed on the server.") from exc

    messages: list[dict] = []
    for turn in history or []:
        role = turn.get("role")
        content = turn.get("content")
        if role in ("user", "assistant") and isinstance(content, str) and content.strip():
            messages.append({"role": role, "content": content})

    user_content = f"Alert context (the ONLY data you may reason from):\n{_format_context_for_prompt(context)}\n\nAnalyst question: {question}"
    messages.append({"role": "user", "content": user_content})

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    try:
        response = client.messages.create(
            model=settings.chat_llm_model,
            max_tokens=1024,
            system=_SYSTEM_PROMPT,
            output_config={"effort": "medium"},
            messages=messages,
        )
    except anthropic.APIStatusError as exc:
        logger.exception("LLM call failed for alert chat.")
        raise LlmUnavailableError(f"The LLM explanation service returned an error: {exc}") from exc
    except anthropic.APIConnectionError as exc:
        logger.exception("LLM call failed for alert chat.")
        raise LlmUnavailableError("Could not reach the LLM explanation service.") from exc
    except Exception as exc:  # anything else (unexpected SDK/runtime error) -- degrade, don't crash the request
        logger.exception("LLM call failed for alert chat.")
        raise LlmUnavailableError("The LLM explanation service failed unexpectedly.") from exc

    text = "".join(block.text for block in response.content if getattr(block, "type", None) == "text").strip()
    if not text:
        raise LlmUnavailableError("The LLM explanation service returned an empty response.")

    classifier_shap = context["classifier_shap"]
    anomaly_shap = context["anomaly_shap"]
    return ChatAnswer(
        text,
        ChatSources(
            prediction=True,
            shap=bool(classifier_shap or anomaly_shap),
            feature_values=bool(context["relevant_feature_values"]),
            glossary=bool(context["feature_glossary"]),
        ),
    )


def answer_question(question: str, context: dict, history: list[dict] | None = None) -> ChatAnswer:
    """Entry point: try the deterministic matcher first, fall back to the LLM, never crash the caller."""
    deterministic = try_deterministic_answer(question, context)
    if deterministic is not None:
        return deterministic

    try:
        return answer_with_llm(question, context, history)
    except LlmUnavailableError as exc:
        return ChatAnswer(
            "I can't generate a free-form explanation for that question right now (the AI explanation "
            f"service is unavailable: {exc}). You can still ask about specific numbers -- confidence, "
            "anomaly score, risk score/level, top contributing features, or a feature's definition.",
            ChatSources(),
        )
