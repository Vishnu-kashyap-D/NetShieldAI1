import type { RiskLevel, ShapDirection } from "../../types/api";
import { parseShapFeatures } from "../../data/shap";
import { SectionCard } from "../common/SectionCard";
import { BarList } from "../common/BarList";
import "./ShapExplanationCard.css";

type ShapKind = "classifier" | "anomaly";

const CONFIG: Record<
  ShapKind,
  { title: string; description: string; accent: "brand" | "teal"; directionMeaning: string }
> = {
  classifier: {
    title: "Classifier explanation",
    description: "Features contributing to this model output — the BiLSTM classifier's predicted category.",
    accent: "brand",
    directionMeaning:
      "This explains the predicted class's probability, relative to this explanation's background sample. " +
      "Positive means the feature increased that probability; negative means it decreased it — not automatically " +
      "\"toward BENIGN,\" since it may reflect movement toward any other category. This is an attribution of the " +
      "model's output, not proof of causation.",
  },
  anomaly: {
    title: "Anomaly explanation",
    description: "Features contributing to this model output — the Autoencoder's anomaly (reconstruction error) score.",
    accent: "teal",
    directionMeaning:
      "This explains the reconstruction-error output, relative to this explanation's background sample. Positive " +
      "means the feature increased that error (more anomalous); negative means it decreased it (more normal-looking). " +
      "This is an attribution of the model's output, not proof of causation.",
  },
};

const DIRECTION_LABEL: Record<ShapDirection, string> = {
  positive: "+",
  negative: "−",
  neutral: "0",
  unknown: "?",
};

interface ShapExplanationCardProps {
  kind: ShapKind;
  /** Raw top_classifier_features / top_anomaly_features JSON string from AlertOut, or null. */
  raw: string | null;
  riskLevel: RiskLevel;
}

/**
 * One SHAP explanation panel (classifier or anomaly) -- kept as two entirely
 * separate cards rather than merged, since they explain two different model
 * outputs (cyber_ai/explain.py's explain_classifier_windows and
 * explain_autoencoder_windows are independent computations). The bar itself
 * stays a single-hue magnitude display (BarList is deliberately unsigned --
 * see its own doc comment), sized by `mean_abs_shap`; the +/-/0/? chip in
 * front of each row is the only signed element, sourced from `direction`
 * (cyber_ai/explain.py::_top_features). Older alerts scored before the
 * signed-SHAP change only have `mean_abs_shap` -- those rows show "?" rather
 * than guessing a sign that was never computed for them.
 */
export function ShapExplanationCard({ kind, raw, riskLevel }: ShapExplanationCardProps) {
  const { title, description, accent, directionMeaning } = CONFIG[kind];
  const features = parseShapFeatures(raw)
    .slice()
    .sort((a, b) => b.mean_abs_shap - a.mean_abs_shap);

  return (
    <SectionCard title={title} subtitle={description}>
      {features.length > 0 ? (
        <>
          <BarList
            items={features.map((f) => {
              const direction = f.direction ?? "unknown";
              return {
                key: f.feature,
                label: f.feature,
                value: Math.abs(f.mean_abs_shap),
                displayValue: `${DIRECTION_LABEL[direction]} ${f.mean_abs_shap.toFixed(4)}`,
                labelPrefix: (
                  <span className={`shap-direction-chip shap-direction-chip--${direction}`} title={`Direction: ${direction}`}>
                    {DIRECTION_LABEL[direction]}
                  </span>
                ),
              };
            })}
            labelWidth="220px"
            accent={accent}
          />
          <p className="shap-caveat">
            Bars are ranked by mean absolute SHAP contribution (magnitude, regardless of direction) — this shows
            which features drove the model's output, not proof that any single feature caused the underlying traffic
            to be an attack. {directionMeaning}
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
