import type { RiskLevel } from "../../types/api";
import { parseShapFeatures } from "../../data/shap";
import { SectionCard } from "../common/SectionCard";
import { BarList } from "../common/BarList";
import "./ShapExplanationCard.css";

type ShapKind = "classifier" | "anomaly";

const CONFIG: Record<ShapKind, { title: string; description: string; accent: "brand" | "teal" }> = {
  classifier: {
    title: "Classifier explanation",
    description: "Features contributing to this model output — the BiLSTM classifier's predicted category.",
    accent: "brand",
  },
  anomaly: {
    title: "Anomaly explanation",
    description: "Features contributing to this model output — the Autoencoder's anomaly (reconstruction error) score.",
    accent: "teal",
  },
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
 * explain_autoencoder_windows are independent computations). Each row's value
 * is `mean_abs_shap` -- an unsigned magnitude (see cyber_ai/explain.py::_top_features);
 * the backend does not store a signed/directional SHAP value, so this
 * deliberately never implies a positive/negative split that isn't there.
 */
export function ShapExplanationCard({ kind, raw, riskLevel }: ShapExplanationCardProps) {
  const { title, description, accent } = CONFIG[kind];
  const features = parseShapFeatures(raw)
    .slice()
    .sort((a, b) => b.mean_abs_shap - a.mean_abs_shap);

  return (
    <SectionCard title={title} subtitle={description}>
      {features.length > 0 ? (
        <>
          <BarList
            items={features.map((f) => ({
              key: f.feature,
              label: f.feature,
              value: Math.abs(f.mean_abs_shap),
              displayValue: f.mean_abs_shap.toFixed(4),
            }))}
            labelWidth="220px"
            accent={accent}
          />
          <p className="shap-caveat">
            Ranked by mean absolute SHAP contribution — this shows which features drove the model's output, not proof
            that any single feature caused the underlying traffic to be an attack.
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
