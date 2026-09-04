import type { RiskLevel } from "../../types/api";
import { parseShapFeatures } from "../../data/shap";
import { FEATURE_GLOSSARY } from "../../data/featureGlossary";
import { SectionCard } from "../common/SectionCard";
import { ShapDivergingBars } from "./ShapDivergingBars";
import "./ShapExplanationCard.css";

type ShapKind = "classifier" | "anomaly";

// Exact technical meaning per kind -- SHAP explains one specific model output, relative
// to the background sample used for that explanation call. Classifier: never say
// "toward BENIGN" for a negative value -- it only means the predicted class's own
// output went down, not that any other specific class (BENIGN or otherwise) went up.
const CONFIG: Record<
  ShapKind,
  { title: string; description: string; positiveCaption: string; negativeCaption: string; note: string }
> = {
  classifier: {
    title: "Classifier explanation",
    description: "Why the BiLSTM classifier predicted this category.",
    positiveCaption: "Increased predicted-class output",
    negativeCaption: "Decreased predicted-class output",
    note:
      "Relative to the background sample used for this explanation. A decreased value means the predicted class's " +
      "own output went down -- it does not mean the traffic was pushed toward BENIGN specifically, or toward any " +
      "other single category this data identifies.",
  },
  anomaly: {
    title: "Anomaly explanation",
    description: "Why the Autoencoder scored this window as anomalous.",
    positiveCaption: "Increased anomaly contribution",
    negativeCaption: "Decreased anomaly contribution",
    note:
      "Relative to the background sample used for this explanation. An increased value made the reconstruction " +
      "error higher (more anomalous); a decreased value made it lower (more like normal traffic).",
  },
};

interface ShapExplanationCardProps {
  kind: ShapKind;
  /** Raw top_classifier_features / top_anomaly_features JSON string from AlertOut, or null. */
  raw: string | null;
  riskLevel: RiskLevel;
}

/**
 * One SHAP explanation panel (classifier or anomaly) -- two separate cards, since they
 * explain two different model outputs (cyber_ai/explain.py's explain_classifier_windows
 * and explain_autoencoder_windows are independent computations). Uses the real signed
 * shap_value/direction already computed server-side -- this component never re-derives,
 * approximates, or recalculates a SHAP value; it only renders what's already stored.
 */
export function ShapExplanationCard({ kind, raw, riskLevel }: ShapExplanationCardProps) {
  const { title, description, positiveCaption, negativeCaption, note } = CONFIG[kind];
  const features = parseShapFeatures(raw)
    .slice()
    .sort((a, b) => b.mean_abs_shap - a.mean_abs_shap);

  return (
    <SectionCard title={title} subtitle={description} className="shap-card">
      {features.length > 0 ? (
        <>
          <ShapDivergingBars
            features={features}
            positiveCaption={positiveCaption}
            negativeCaption={negativeCaption}
            glossary={FEATURE_GLOSSARY}
          />
          <p className="shap-caveat">
            Ranked by magnitude (mean absolute SHAP), regardless of direction -- this shows which features drove the
            model's output, not proof that any single feature caused the underlying traffic to be an attack. {note}
          </p>
        </>
      ) : (
        <div className="empty-state shap-empty">
          <div className="glyph">&#9676;</div>
          <div>Explanation unavailable for this alert.</div>
          <div className="shap-empty-reason">{unavailableReason(riskLevel)}</div>
        </div>
      )}
    </SectionCard>
  );
}

function unavailableReason(riskLevel: RiskLevel): string {
  if (riskLevel === "Low") {
    return "SHAP explanations are only generated for Medium/High risk alerts — this window was scored Low risk.";
  }
  return "This alert wasn't scored with SHAP explanations enabled at ingest time.";
}
