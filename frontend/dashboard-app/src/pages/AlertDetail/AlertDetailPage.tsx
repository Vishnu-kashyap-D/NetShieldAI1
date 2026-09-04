import { Link, useParams } from "react-router-dom";
import type { AlertDetailOut } from "../../types/api";
import { useDataProvider } from "../../data/DataModeContext";
import { usePolledAsync } from "../../hooks/usePolledAsync";
import { ApiUnavailableError, NotFoundError } from "../../data/errors";
import { RiskBadge } from "../../components/common/RiskBadge";
import { SectionCard } from "../../components/common/SectionCard";
import { MetricCard } from "../../components/alertDetail/MetricCard";
import { DetectionInfoGrid, type DetectionInfoItem } from "../../components/alertDetail/DetectionInfoGrid";
import { ShapExplanationCard } from "../../components/alertDetail/ShapExplanationCard";
import { FeedbackSection } from "../../components/alertDetail/FeedbackSection";
import { RawFeaturesSection } from "../../components/alertDetail/RawFeaturesSection";
import { formatFullDateTime, formatPercent } from "../../utils/format";
import "./AlertDetailPage.css";

export function AlertDetailPage() {
  const { id } = useParams();
  const provider = useDataProvider();
  const alertId = Number(id);
  const validId = id !== undefined && Number.isFinite(alertId) && alertId > 0;

  const result = usePolledAsync(
    () => {
      if (!validId) throw new NotFoundError(`"${id}" is not a valid alert ID.`);
      return provider.getAlert(alertId);
    },
    [provider, id],
  );

  const dataSourceNotice = provider.getDataSourceNotice();

  return (
    <section className="alert-detail-page">
      <Link to="/alerts" className="back-link">
        <svg viewBox="0 0 24 24" fill="none" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M19 12H5" />
          <path d="M12 19l-7-7 7-7" />
        </svg>
        Back to Alerts
      </Link>

      {dataSourceNotice && <div className="data-source-notice">{dataSourceNotice}</div>}

      {result.status === "loading" && !result.hasLoadedOnce && (
        <div className="card">
          <div className="empty-state" role="status" aria-live="polite">
            <div className="skeleton" style={{ height: 14, width: "50%", margin: "0 auto 10px" }} />
            <div className="skeleton" style={{ height: 14, width: "35%", margin: "0 auto" }} />
          </div>
        </div>
      )}

      {result.status === "error" && (
        <div className="card">
          {result.error instanceof NotFoundError ? (
            <div className="empty-state">
              <div className="glyph">&#9676;</div>
              Alert {id} was not found. It may have been from a different session or data mode.
            </div>
          ) : result.error instanceof ApiUnavailableError ? (
            <div className="error-state" role="alert">
              Couldn't load this alert: {result.error.message}
            </div>
          ) : (
            <div className="error-state" role="alert">
              Couldn't load this alert{result.error ? `: ${result.error.message}` : "."}
            </div>
          )}
        </div>
      )}

      {result.status === "success" && result.data && <AlertDetailContent alert={result.data} />}
    </section>
  );
}

function AlertDetailContent({ alert }: { alert: AlertDetailOut }) {
  const detectionInfo: DetectionInfoItem[] = [
    { key: "window_start", label: "Window start", value: alert.window_start },
    { key: "window_end", label: "Window end", value: alert.window_end },
    { key: "source_file", label: "Source file", value: alert.source_file },
    { key: "batch_id", label: "Batch ID", value: alert.batch_id },
    { key: "ingested_at", label: "Ingested at", value: formatFullDateTime(alert.ingested_at) },
    { key: "actual_label", label: "Actual label (ground truth)", value: alert.actual_label },
    { key: "actual_category", label: "Actual category (ground truth)", value: alert.actual_category },
    { key: "predicted_label", label: "Predicted label", value: alert.predicted_label },
    { key: "pipeline_action", label: "Pipeline action", value: alert.pipeline_action },
  ];

  return (
    <>
      <header className="alert-detail-header">
        <div className="alert-detail-title-row">
          <h1>{alert.predicted_label}</h1>
          <RiskBadge level={alert.risk_level} />
        </div>
        <div className="alert-detail-subtitle">
          Alert #{alert.id} · {alert.pipeline_action} · {formatFullDateTime(alert.ingested_at)}
        </div>
      </header>

      <div className="metric-grid">
        <MetricCard
          label="Confidence"
          value={alert.is_anomaly ? formatPercent(alert.confidence) : "N/A"}
          help={
            alert.is_anomaly
              ? "How sure the BiLSTM classifier is about the predicted category."
              : "Not computed — the anomaly gate never passed this window to the classifier."
          }
        />
        <MetricCard
          label="Anomaly score"
          value={alert.anomaly_score.toFixed(4)}
          help="The Autoencoder's reconstruction error for this window — higher means it looked less like normal traffic."
        />
        <MetricCard
          label="Anomaly threshold"
          value={alert.anomaly_threshold.toFixed(4)}
          help="The calibrated cutoff this window's anomaly score was compared against."
        />
        <MetricCard
          label="Risk score"
          value={alert.risk_score.toFixed(4)}
          help="Fused score: the higher of the normalized anomaly score and the classifier's confidence."
        />
        <MetricCard label="Risk level" value={<RiskBadge level={alert.risk_level} />} help="Low/Medium/High bucket from the calibrated risk-score cutoffs." />
        <MetricCard
          label="Is anomaly"
          value={alert.is_anomaly ? "Yes" : "No"}
          help="Whether the anomaly gate flagged this window at all — only flagged windows reach the classifier."
        />
      </div>

      <SectionCard title="Detection information" subtitle="Window and pipeline metadata for this alert">
        <DetectionInfoGrid items={detectionInfo} />
      </SectionCard>

      <div className="shap-grid">
        <ShapExplanationCard kind="classifier" raw={alert.top_classifier_features} riskLevel={alert.risk_level} />
        <ShapExplanationCard kind="anomaly" raw={alert.top_anomaly_features} riskLevel={alert.risk_level} />
      </div>

      <FeedbackSection alert={alert} />

      <SectionCard title="Raw model features" subtitle="The full standardized feature vector for this window's last row">
        <RawFeaturesSection features={alert.features} />
      </SectionCard>
    </>
  );
}
