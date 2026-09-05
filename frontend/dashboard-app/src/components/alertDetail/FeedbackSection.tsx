import { useState } from "react";
import type { AlertDetailOut, AttackCategory, FeedbackOut } from "../../types/api";
import { useDataProvider } from "../../data/DataModeContext";
import { useSession } from "../../auth/session";
import { CAN_SUBMIT_FEEDBACK, roleCan } from "../../auth/permissions";
import { usePolledAsync } from "../../hooks/usePolledAsync";
import { CATEGORY_ORDER } from "../../constants/taxonomy";
import { SectionCard } from "../../components/common/SectionCard";
import { RiskBadge } from "../../components/common/RiskBadge";
import { ApiUnavailableError } from "../../data/errors";
import { formatFullDateTime, formatPercent } from "../../utils/format";
import "./FeedbackSection.css";

type Verdict = "agree" | "correct" | null;

/**
 * Analyst feedback for one alert -- POST /api/feedback (backend/app/routers/feedback.py).
 * The real API only accepts a single `validated_label` string (plus optional analyst/notes);
 * there is no separate "correct/incorrect" flag on the backend. This UI maps the analyst's
 * two-step choice (confirm vs. correct) onto that one field: confirming submits the AI's
 * own predicted_label back as the validated_label, correcting submits whichever category
 * the analyst picks. Either way, the original AI prediction shown above is never altered.
 */
export function FeedbackSection({ alert }: { alert: AlertDetailOut }) {
  const provider = useDataProvider();
  const { analyst } = useSession();

  const [verdict, setVerdict] = useState<Verdict>(null);
  const [correctedLabel, setCorrectedLabel] = useState<AttackCategory | "">("");
  const [notes, setNotes] = useState("");
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  const [submitState, setSubmitState] = useState<"idle" | "submitting" | "success" | "error">("idle");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [lastSubmitted, setLastSubmitted] = useState<FeedbackOut | null>(null);
  // The backend's FeedbackOut response doesn't echo `notes` back (see
  // backend/app/schemas.py -- the Feedback row stores it, but the response
  // schema omits it), so "here's what you submitted" for notes comes from this
  // component's own form state at submit time, not from the API response.
  const [submittedNotes, setSubmittedNotes] = useState<string>("");

  // GET /api/feedback only supports a global listing (no alert_id filter param on the
  // real endpoint) -- filtering to this alert is done client-side over that same list,
  // not a fabricated "feedback by alert" API capability.
  const feedbackList = usePolledAsync(() => provider.listFeedback(), [provider]);
  const historyForAlert = (feedbackList.data ?? []).filter((f) => f.alert_id === alert.id);
  const canSubmitFeedback = roleCan(analyst?.role, CAN_SUBMIT_FEEDBACK);

  function resetForm() {
    setVerdict(null);
    setCorrectedLabel("");
    setNotes("");
    setValidationMessage(null);
    setSubmitState("idle");
    setSubmitError(null);
  }

  async function handleSubmit() {
    if (verdict === null) {
      setValidationMessage("Choose whether the prediction is correct before submitting.");
      return;
    }
    if (verdict === "correct" && !correctedLabel) {
      setValidationMessage("Select the validated classification before submitting.");
      return;
    }
    setValidationMessage(null);

    const validatedLabel = verdict === "agree" ? alert.predicted_label : correctedLabel;
    setSubmitState("submitting");
    setSubmitError(null);
    try {
      const result = await provider.submitFeedback({
        alert_id: alert.id,
        validated_label: validatedLabel,
        analyst: analyst?.name ?? null,
        notes: notes.trim() || undefined,
      });
      setLastSubmitted(result);
      setSubmittedNotes(notes.trim());
      setSubmitState("success");
      feedbackList.refresh();
    } catch (err) {
      setSubmitState("error");
      setSubmitError(
        err instanceof ApiUnavailableError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Could not submit feedback.",
      );
    }
  }

  return (
    <SectionCard
      title="Analyst feedback"
      subtitle="Review the AI prediction and submit a validated classification"
      className="feedback-section"
    >
      <div className="feedback-prediction">
        <div className="feedback-prediction-label">AI prediction (unchanged by feedback)</div>
        <div className="feedback-prediction-row">
          <span className="feedback-prediction-category">{alert.predicted_label}</span>
          <RiskBadge level={alert.risk_level} />
          {alert.is_anomaly && <span className="feedback-prediction-confidence">{formatPercent(alert.confidence)} confidence</span>}
        </div>
      </div>

      {submitState === "success" && lastSubmitted ? (
        <div className="feedback-confirmation">
          <div className="feedback-confirmation-title">Feedback submitted</div>
          <div className="feedback-confirmation-body">
            Validated classification: <b>{lastSubmitted.validated_label}</b>
            {lastSubmitted.analyst && (
              <>
                {" "}
                · Analyst: <b>{lastSubmitted.analyst}</b>
              </>
            )}
            {" "}
            · {formatFullDateTime(lastSubmitted.created_at)}
          </div>
          {submittedNotes && (
            <div className="feedback-confirmation-notes">
              <span className="feedback-confirmation-notes-label">Your note:</span> {submittedNotes}
            </div>
          )}
          <p className="feedback-caveat">
            This correction has been recorded and is available the next time a retraining run is triggered. It does
            not change this alert's prediction, and the model itself has not been retrained yet.
          </p>
          <button className="btn" onClick={resetForm}>
            Submit another correction
          </button>
        </div>
      ) : !canSubmitFeedback ? (
        <div className="feedback-caveat" role="note">
          Your role ({analyst?.role ?? "unknown"}) can't submit feedback — this action requires Security Analyst,
          Threat Hunter, or Administrator. You can still review feedback history below.
        </div>
      ) : (
        <div className="feedback-form">
          <div className="feedback-question">Is the AI prediction above correct?</div>
          <div className="feedback-verdict-row">
            <button
              type="button"
              className={`btn feedback-verdict-btn${verdict === "agree" ? " active" : ""}`}
              onClick={() => {
                setVerdict("agree");
                setValidationMessage(null);
              }}
              disabled={submitState === "submitting"}
            >
              Yes, confirm prediction
            </button>
            <button
              type="button"
              className={`btn feedback-verdict-btn${verdict === "correct" ? " active" : ""}`}
              onClick={() => {
                setVerdict("correct");
                setValidationMessage(null);
              }}
              disabled={submitState === "submitting"}
            >
              No, correct it
            </button>
          </div>

          {verdict === "correct" && (
            <div className="field">
              <label htmlFor="fbCorrectedLabel">Validated classification</label>
              <select
                id="fbCorrectedLabel"
                value={correctedLabel}
                onChange={(e) => setCorrectedLabel(e.target.value as AttackCategory)}
                disabled={submitState === "submitting"}
              >
                <option value="">Select a category…</option>
                {CATEGORY_ORDER.map((category) => (
                  <option key={category} value={category}>
                    {category}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="field">
            <label htmlFor="fbNotes">Notes (optional)</label>
            <textarea
              id="fbNotes"
              placeholder="Optional context for this correction…"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              disabled={submitState === "submitting"}
            />
          </div>

          {validationMessage && (
            <div className="feedback-validation" role="alert">
              {validationMessage}
            </div>
          )}
          {submitState === "error" && submitError && (
            <div className="error-state feedback-submit-error" role="alert">
              Couldn't submit feedback: {submitError}
            </div>
          )}

          <button className="btn primary" onClick={handleSubmit} disabled={submitState === "submitting"}>
            {submitState === "submitting" ? "Submitting…" : "Submit feedback"}
          </button>
        </div>
      )}

      {historyForAlert.length > 0 && (
        <div className="feedback-history">
          <div className="feedback-history-title">Feedback history for this alert</div>
          <div className="feedback-history-note">
            From GET /api/feedback (the global feedback log), filtered to this alert's ID — the API doesn't return
            each entry's notes, so only the validated label, analyst, and time are shown here.
          </div>
          {historyForAlert.map((entry) => (
            <div className="feedback-history-row" key={entry.id}>
              <span className="feedback-history-label">{entry.validated_label}</span>
              <span className="feedback-history-analyst">{entry.analyst ?? "Unknown analyst"}</span>
              <span className="feedback-history-time">{formatFullDateTime(entry.created_at)}</span>
            </div>
          ))}
        </div>
      )}
    </SectionCard>
  );
}
