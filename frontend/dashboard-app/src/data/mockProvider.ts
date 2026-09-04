import type { DataProvider, AlertListParams, IngestParams, TimeseriesParams } from "./DataProvider";
import type {
  AlertDetailOut,
  AlertListOut,
  AlertOut,
  AttackCategory,
  FeedbackIn,
  FeedbackOut,
  HealthOut,
  IngestSummaryOut,
  RetrainTriggerIn,
  RiskLevel,
  StatsSummaryOut,
  TimeseriesPointOut,
  TrainingRunOut,
} from "../types/api";
import { NotFoundError, RetrainAlreadyRunningError } from "./errors";
import { buildFeatureVector } from "./mock/featureTemplates";
import { buildShapJson, generateMockAlerts, toAlertDetail, type GeneratedAlert } from "./mock/mockDataset";
import { createRng, randInt } from "./mock/random";
import type { SimulatedWorkflowEvent } from "./mock/scenario";

const MOCK_DATA_NOTICE = "Demo data -- generated locally, not live output from the trained model.";

// Mirrors cyber_ai.feedback._feedback_label / backend/app/routers/feedback.py's
// _feedback_label: a "this was a false alarm" correction is stored as BENIGN, the
// Autoencoder's actual training label -- not the literal word "Normal".
const NORMAL_ALIASES = new Set(["normal", "normal / ignored", "benign"]);
function feedbackLabel(value: string): string {
  return NORMAL_ALIASES.has(value.trim().toLowerCase()) ? "BENIGN" : value.trim();
}

function matchesFilters(alert: AlertOut, params: AlertListParams | undefined): boolean {
  if (!params) return true;
  if (params.risk_level && alert.risk_level !== params.risk_level) return false;
  if (params.category && alert.predicted_label !== params.category) return false;
  if (params.source_file && alert.source_file !== params.source_file) return false;
  if (params.batch_id && alert.batch_id !== params.batch_id) return false;
  return true;
}

/** Synthetic training metrics shaped like cyber_ai.train's real output, perturbed per run. */
function buildSyntheticMetrics(rng: ReturnType<typeof createRng>): Record<string, unknown> {
  const jitterPct = (base: number) => Math.round((base + (rng() - 0.5) * 0.02) * 1000) / 1000;
  return {
    note: "Synthetic metrics for demo mode -- no real training subprocess ran.",
    autoencoder: { balanced_accuracy: jitterPct(0.718), recall_on_anomalies: jitterPct(0.519) },
    classifier: {
      weighted_f1: jitterPct(0.97),
      macro_f1: jitterPct(0.53),
      per_class_f1: {
        "DoS / DDoS": jitterPct(0.978),
        "Port Scanning": jitterPct(0.996),
        "Brute Force": jitterPct(0.717),
        "Botnet Activity": jitterPct(0.184),
        "Malware Traffic": jitterPct(0.304),
        "Data Exfiltration": 0,
      },
    },
  };
}

/**
 * Generates and serves a realistic-looking alert dataset entirely in-memory, without
 * touching the real backend, database, or trained model. Implements the exact same
 * DataProvider contract as RealApiProvider so components never need to know which
 * one they're talking to.
 */
export class MockDataProvider implements DataProvider {
  readonly mode = "mock" as const;

  private alerts: GeneratedAlert[];
  private feedback: FeedbackOut[] = [];
  private trainingRuns: TrainingRunOut[] = [];
  private nextAlertId: number;
  private nextFeedbackId = 1;
  private nextRunId = 1;
  private rng = createRng(1337);

  // Demo Scenario state -- lives on the provider (not any one component) so the
  // scripted run keeps going when the presenter navigates away from the Dashboard
  // to inspect the alert it just created (exactly the intended demo workflow) and
  // comes back later. See simulateLiveIncident() below.
  private scenarioRunning = false;
  private scenarioLog: SimulatedWorkflowEvent[] = [];
  private scenarioListeners = new Set<(event: SimulatedWorkflowEvent) => void>();

  constructor(seed = 42) {
    this.alerts = generateMockAlerts(seed);
    this.nextAlertId = this.alerts.length + 1;
  }

  getDataSourceNotice(): string {
    return MOCK_DATA_NOTICE;
  }

  async getHealth(): Promise<HealthOut> {
    return {
      status: "ok (demo mode)",
      model_loaded: true,
      feature_count: 76,
      artifacts_dir: "(mock provider -- no real artifacts loaded)",
    };
  }

  async listAlerts(params?: AlertListParams): Promise<AlertListOut> {
    const matching = this.alerts.map((entry) => entry.alert).filter((alert) => matchesFilters(alert, params));
    matching.sort((a, b) => b.ingested_at.localeCompare(a.ingested_at) || b.id - a.id);

    const limit = Math.min(500, Math.max(1, params?.limit ?? 50));
    const offset = Math.max(0, params?.offset ?? 0);
    const items = matching.slice(offset, offset + limit);

    return { total: matching.length, limit, offset, items };
  }

  async getAlert(id: number): Promise<AlertDetailOut> {
    const entry = this.alerts.find((e) => e.alert.id === id);
    if (!entry) throw new NotFoundError(`Alert ${id} not found`);
    return toAlertDetail(entry);
  }

  async getStatsSummary(): Promise<StatsSummaryOut> {
    const riskLevelCounts: Record<string, number> = {};
    const categoryCounts: Record<string, number> = {};
    let anomalyCount = 0;

    for (const { alert } of this.alerts) {
      riskLevelCounts[alert.risk_level] = (riskLevelCounts[alert.risk_level] ?? 0) + 1;
      categoryCounts[alert.predicted_label] = (categoryCounts[alert.predicted_label] ?? 0) + 1;
      if (alert.is_anomaly) anomalyCount++;
    }

    return {
      total_alerts: this.alerts.length,
      risk_level_counts: riskLevelCounts,
      category_counts: categoryCounts,
      anomaly_count: anomalyCount,
    };
  }

  async getTimeseries(params?: TimeseriesParams): Promise<TimeseriesPointOut[]> {
    const minutes = params?.minutes ?? 60;
    const bucketSeconds = params?.bucket_seconds ?? 30;
    const since = Date.now() - minutes * 60_000;
    const bucketMs = bucketSeconds * 1000;

    const buckets = new Map<number, { count: number; high: number; medium: number; low: number }>();
    for (const { alert } of this.alerts) {
      const ts = new Date(alert.ingested_at).getTime();
      if (ts < since) continue;
      const bucketKey = Math.floor(ts / bucketMs) * bucketMs;
      const bucket = buckets.get(bucketKey) ?? { count: 0, high: 0, medium: 0, low: 0 };
      bucket.count++;
      if (alert.risk_level === "High") bucket.high++;
      else if (alert.risk_level === "Medium") bucket.medium++;
      else bucket.low++;
      buckets.set(bucketKey, bucket);
    }

    return [...buckets.entries()]
      .sort(([a], [b]) => a - b)
      .map(([bucketMsKey, counts]) => ({ bucket: new Date(bucketMsKey).toISOString(), ...counts }));
  }

  private appendSyntheticBatch(sourceFile: string, count: number): IngestSummaryOut {
    const batchId = `mock-ingest-${Date.now().toString(16)}`;
    const categories: AttackCategory[] = ["Normal", "Normal", "Normal", "DoS / DDoS", "Port Scanning", "Botnet Activity"];
    const riskCounts: Record<string, number> = {};
    const labelCounts: Record<string, number> = {};
    let windowStart = 0;
    let anomalousWindows = 0;

    for (let i = 0; i < count; i++) {
      const category = categories[randInt(this.rng, 0, categories.length - 1)];
      const isAnomaly = category !== "Normal";
      const anomalyScore = isAnomaly ? 0.9 + this.rng() * 1.5 : 0.1 + this.rng() * 0.5;
      const confidence = isAnomaly ? 0.7 + this.rng() * 0.29 : 0;
      const riskScore = Math.max(confidence, Math.min(1, anomalyScore / 1.9));
      const riskLevel: RiskLevel = riskScore >= 0.9968 ? "High" : riskScore >= 0.3569 ? "Medium" : "Low";
      if (isAnomaly) anomalousWindows++;

      // Mirrors the real backend: SHAP is only ever computed for anomalous
      // Medium/High-risk windows (backend/app/detection_service.py). `category`
      // is never "Normal" here when isAnomaly is true (see predicted_label below;
      // TS narrows `category` through the `isAnomaly` alias), so this reuses the
      // exact same generator generateMockAlerts() uses for the base dataset
      // instead of inventing a new SHAP shape.
      let topClassifierFeatures: string | null = null;
      let topAnomalyFeatures: string | null = null;
      if (isAnomaly && riskLevel !== "Low") {
        topClassifierFeatures = buildShapJson(this.rng, category);
        topAnomalyFeatures = buildShapJson(this.rng, category);
      }

      const alert: AlertOut = {
        id: this.nextAlertId++,
        batch_id: batchId,
        window_start: windowStart,
        window_end: windowStart + 9,
        source_file: sourceFile,
        actual_label: category === "Normal" ? "BENIGN" : category,
        actual_category: category,
        predicted_label: isAnomaly ? category : "Normal",
        confidence: Math.round(confidence * 1e6) / 1e6,
        anomaly_score: Math.round(anomalyScore * 1e6) / 1e6,
        anomaly_threshold: 0.834375,
        is_anomaly: isAnomaly,
        pipeline_action: isAnomaly ? "Classified and alerted" : "Ignored as normal",
        risk_score: Math.round(riskScore * 1e6) / 1e6,
        risk_level: riskLevel,
        top_classifier_features: topClassifierFeatures,
        top_anomaly_features: topAnomalyFeatures,
        ingested_at: new Date().toISOString(),
      };
      this.alerts.push({ alert, features: buildFeatureVector(this.rng, category) });
      riskCounts[riskLevel] = (riskCounts[riskLevel] ?? 0) + 1;
      labelCounts[alert.predicted_label] = (labelCounts[alert.predicted_label] ?? 0) + 1;
      windowStart += 5;
    }

    return {
      batch_id: batchId,
      source: sourceFile,
      windows_scored: count,
      anomalous_windows: anomalousWindows,
      alerts_written: count,
      risk_level_counts: riskCounts,
      predicted_label_counts: labelCounts,
    };
  }

  async ingestDemo(_params?: IngestParams): Promise<IngestSummaryOut> {
    return this.appendSyntheticBatch("panel_demo_traffic.csv", 20);
  }

  async ingestCsv(file: File, _params?: IngestParams): Promise<IngestSummaryOut> {
    // Mock mode doesn't parse the uploaded file's contents (there's no model behind
    // it to score real rows with) -- it appends a synthetic batch tagged with the
    // file's name so the calling UI still sees a realistic-shaped response.
    return this.appendSyntheticBatch(file.name, 15);
  }

  async submitFeedback(payload: FeedbackIn): Promise<FeedbackOut> {
    const entry = this.alerts.find((e) => e.alert.id === payload.alert_id);
    if (!entry) throw new NotFoundError(`Alert ${payload.alert_id} not found`);

    const feedback: FeedbackOut = {
      id: this.nextFeedbackId++,
      alert_id: payload.alert_id,
      validated_label: feedbackLabel(payload.validated_label),
      analyst: payload.analyst ?? null,
      written_to_feedback_store: true,
      created_at: new Date().toISOString(),
    };
    this.feedback.unshift(feedback);
    return feedback;
  }

  async listFeedback(): Promise<FeedbackOut[]> {
    return [...this.feedback];
  }

  async triggerRetrain(payload?: RetrainTriggerIn): Promise<TrainingRunOut> {
    const alreadyRunning = this.trainingRuns.find((r) => r.status === "running");
    if (alreadyRunning) throw new RetrainAlreadyRunningError(alreadyRunning.id);

    const run: TrainingRunOut = {
      id: this.nextRunId++,
      status: "running",
      triggered_by: payload?.triggered_by ?? null,
      feedback_rows_used: this.feedback.length,
      metrics: null,
      error: null,
      started_at: new Date().toISOString(),
      finished_at: null,
    };
    this.trainingRuns.unshift(run);

    // Real retraining takes ~8 minutes (Deep-Dive report, Chapter 7.2); a demo can't
    // wait that long, so this simulates completion on a short timer instead. Still
    // clearly a simulation -- metrics are synthetic (see buildSyntheticMetrics).
    setTimeout(() => {
      run.status = "completed";
      run.metrics = buildSyntheticMetrics(this.rng);
      run.finished_at = new Date().toISOString();
    }, 12_000);

    return run;
  }

  async listRetrainRuns(): Promise<TrainingRunOut[]> {
    return [...this.trainingRuns];
  }

  async getRetrainRun(id: number): Promise<TrainingRunOut> {
    const run = this.trainingRuns.find((r) => r.id === id);
    if (!run) throw new NotFoundError(`Training run ${id} not found`);
    return run;
  }

  /**
   * Mock-only, not part of the DataProvider interface: subscribes to the Demo
   * Scenario's events, immediately replaying whatever has already happened. Safe to
   * call any time (including when no scenario has started yet -- it just won't
   * replay anything). This is deliberately separate from startScenario() so a
   * component can subscribe on mount without accidentally auto-starting a scenario,
   * and so a component that unmounts (the presenter navigates to inspect the alert
   * the scenario just created) and remounts later reconnects to the *same* run in
   * progress instead of losing it. The returned function only unsubscribes this one
   * listener -- it does not stop the run for anyone else still watching.
   */
  subscribeToScenario(onEvent: (event: SimulatedWorkflowEvent) => void): () => void {
    this.scenarioListeners.add(onEvent);
    for (const event of this.scenarioLog) onEvent(event);
    return () => this.scenarioListeners.delete(onEvent);
  }

  /**
   * Mock-only: starts the scripted "quiet -> suspicious -> alert -> explanation ->
   * feedback -> retrain" narrative described in the Viva Presentation's live-demo
   * slide, entirely client-side and on a compressed timeline, built on top of this
   * provider's own public methods (submitFeedback, triggerRetrain) so its behavior
   * stays consistent with using them directly. A no-op if a run is already in
   * progress -- call subscribeToScenario() to observe it instead of starting a
   * second one.
   */
  startScenario(): void {
    if (this.scenarioRunning) return;
    this.scenarioRunning = true;
    this.scenarioLog = [];

    const broadcast = (event: SimulatedWorkflowEvent) => {
      this.scenarioLog.push(event);
      for (const listener of this.scenarioListeners) listener(event);
    };
    const after = (ms: number, fn: () => void) => setTimeout(fn, ms);

    const burst: { category: Exclude<AttackCategory, "Normal">; label: string }[] = [
      { category: "DoS / DDoS", label: "DDoS burst" },
      { category: "Port Scanning", label: "Port scan burst" },
      { category: "Botnet Activity", label: "Botnet beaconing burst" },
    ];

    let t = 0;
    broadcast({ type: "traffic_state", state: "normal", label: "Quiet -- ordinary background traffic" });
    t += 1500;

    let lastHighRiskAlertId: number | null = null;

    burst.forEach((scene) => {
      after(t, () => broadcast({ type: "traffic_state", state: "suspicious", label: scene.label }));
      t += 800;

      for (let i = 0; i < 4; i++) {
        after(t, () => {
          const summary = this.appendSyntheticBatch("live-simulation.csv", 1);
          const created = this.alerts[this.alerts.length - 1]!.alert;
          // Bias this scene's synthetic alert toward its scripted category/risk so the
          // narrative matches what's announced, while still going through the same
          // appendSyntheticBatch path every other mock ingest uses. Every field that
          // depends on risk (confidence, anomaly_score, risk_score, is_anomaly) is
          // overwritten together so the row stays internally consistent -- a "High"
          // badge next to a 0.09 risk score would be a visible contradiction.
          const isHigh = i < 2;
          const riskLevel: RiskLevel = isHigh ? "High" : "Medium";
          const confidence = isHigh ? 0.9 + this.rng() * 0.099 : 0.7 + this.rng() * 0.2;
          const anomalyScore = 1.0 + this.rng() * 1.5;
          const riskScore = isHigh ? 0.97 + this.rng() * 0.029 : 0.5 + this.rng() * 0.3;

          created.predicted_label = scene.category;
          created.actual_category = scene.category;
          created.is_anomaly = true;
          created.confidence = Math.round(confidence * 1e6) / 1e6;
          created.anomaly_score = Math.round(anomalyScore * 1e6) / 1e6;
          created.risk_score = Math.round(riskScore * 1e6) / 1e6;
          created.risk_level = riskLevel;
          created.pipeline_action = "Classified and alerted";
          // appendSyntheticBatch already decided SHAP for its own randomly-picked
          // category/risk above -- since this scene forces a different category and
          // risk level, its SHAP has to be regenerated to match, or the panel would
          // show features for the wrong category (or be missing for a High-risk
          // alert, which is exactly the bug this fixes). Every scripted burst alert
          // is Medium/High by construction, so it always gets one, same as the real
          // backend would for an anomalous Medium/High window.
          created.top_classifier_features = buildShapJson(this.rng, scene.category);
          created.top_anomaly_features = buildShapJson(this.rng, scene.category);

          broadcast({ type: "alert_created", alert: created });
          lastHighRiskAlertId = created.id;
          after(600, () => broadcast({ type: "explanation_ready", alertId: created.id }));
          void summary;
        });
        t += 700;
      }

      after(t, () => broadcast({ type: "traffic_state", state: "normal", label: "Quiet again" }));
      t += 1500;
    });

    after(t, async () => {
      if (lastHighRiskAlertId === null) return;
      const feedback = await this.submitFeedback({
        alert_id: lastHighRiskAlertId,
        validated_label: this.alerts.find((e) => e.alert.id === lastHighRiskAlertId)?.alert.predicted_label ?? "Normal",
        analyst: "demo-analyst",
        notes: "Confirmed during simulated walkthrough.",
      });
      broadcast({ type: "feedback_recorded", feedback });
    });
    t += 500;

    after(t, async () => {
      try {
        const run = await this.triggerRetrain({ triggered_by: "demo-analyst" });
        broadcast({ type: "retrain_status", run });
        const poll = setInterval(async () => {
          const current = await this.getRetrainRun(run.id);
          broadcast({ type: "retrain_status", run: current });
          if (current.status !== "running") {
            clearInterval(poll);
            this.scenarioRunning = false; // done -- a future startScenario() begins a fresh run
          }
        }, 2000);
      } catch {
        // A run was already in progress outside this scenario (shouldn't normally
        // happen) -- nothing further to narrate, but don't leave the scenario stuck
        // "running" forever.
        this.scenarioRunning = false;
      }
    });
  }
}
