import type { AlertDetailOut, AlertOut, AttackCategory, RiskLevel, ShapFeature } from "../../types/api";
import { buildFeatureVector } from "./featureTemplates";
import { createRng, randInt, weightedChoice } from "./random";
import { SHAP_FEATURE_POOLS } from "./shapPools";

// Calibrated constants pulled directly from docs/NetShieldAI_DeepDive_Report.docx
// (Chapter 3, Steps 5 & 7) -- the real backend's preprocessing.joblib holds these
// exact values. Reusing them means the mock risk math (below) is the same formula
// the real DetectionEngine runs, just fed synthetic inputs instead of real model output.
const ANOMALY_THRESHOLD = 0.834375;
const ANOMALY_SCORE_LOW = 0.0201; // 5th percentile of validation reconstruction errors
const ANOMALY_SCORE_HIGH = 1.8968; // 95th percentile of validation reconstruction errors
const RISK_LOW_CUTOFF = 0.3569; // 90th percentile of BENIGN validation risk scores
const RISK_HIGH_CUTOFF = 0.9968; // median risk score of real attack validation windows

// Relative frequency of each *true* category in the generated dataset. Ordered the
// same way the Deep-Dive report's real class counts are (Chapter 1.4) so rarer
// real-world categories stay rarer here too, just compressed into a usable demo size.
const CATEGORY_WEIGHTS: Record<AttackCategory, number> = {
  Normal: 100,
  "DoS / DDoS": 30,
  "Port Scanning": 18,
  "Brute Force": 12,
  "Botnet Activity": 8,
  "Malware Traffic": 5,
  "Data Exfiltration": 2,
};

// Raw CICIDS2017 labels each category rolls up from (cyber_ai/data.py::ATTACK_CATEGORY_MAP).
const RAW_LABELS_BY_CATEGORY: Record<AttackCategory, readonly string[]> = {
  Normal: ["BENIGN"],
  "DoS / DDoS": ["DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"],
  "Port Scanning": ["PortScan"],
  "Brute Force": ["FTP-Patator", "SSH-Patator", "Web Attack-Brute Force"],
  "Botnet Activity": ["Bot"],
  "Malware Traffic": ["Heartbleed", "Web Attack-XSS", "Web Attack-Sql Injection"],
  "Data Exfiltration": ["Infiltration"],
};

// Probability the anomaly gate (the Autoencoder) actually flags a window of this
// true category as anomalous at all -- loosely tracks the report's discussion of the
// gate's ~54% end-to-end recall (Chapter 5.5/6.2), varied a bit per category so the
// well-supported classes (DoS/DDoS, Port Scanning) come through more reliably than
// the data-starved ones (Data Exfiltration). Normal's value stands in for the ~9.8%
// false-positive rate (Chapter 5.5).
const GATE_PASS_RATE: Record<AttackCategory, number> = {
  Normal: 0.08,
  "DoS / DDoS": 0.95,
  "Port Scanning": 0.93,
  "Brute Force": 0.83,
  "Botnet Activity": 0.78,
  "Malware Traffic": 0.88,
  "Data Exfiltration": 0.45,
};

// Per-true-category classifier confusion, read directly off the real BiLSTM confusion
// matrix in docs/NetShieldAI_DeepDive_Report.docx Chapter 5.1 (row percentages).
// The classifier never predicts "Data Exfiltration" at all in that real matrix (its
// column sums to zero) -- reproduced faithfully here, not an oversight.
const CONFUSION: Record<Exclude<AttackCategory, "Normal">, Partial<Record<Exclude<AttackCategory, "Normal">, number>>> = {
  "Botnet Activity": { "Botnet Activity": 0.644, "Brute Force": 0.169, "DoS / DDoS": 0.017, "Malware Traffic": 0.169 },
  "Brute Force": { "Botnet Activity": 0.09, "Brute Force": 0.738, "DoS / DDoS": 0.012, "Malware Traffic": 0.159 },
  "DoS / DDoS": { "Botnet Activity": 0.0289, "Brute Force": 0.0085, "DoS / DDoS": 0.9584, "Malware Traffic": 0.0043 },
  "Malware Traffic": { "Botnet Activity": 0.04, "Malware Traffic": 0.96 },
  "Port Scanning": {
    "Botnet Activity": 0.0022,
    "Brute Force": 0.004,
    "DoS / DDoS": 0.0004,
    "Malware Traffic": 0.0022,
    "Port Scanning": 0.9912,
  },
  // The real test set had exactly one Data Exfiltration window, and it was missed --
  // classified as Malware Traffic. Not enough real signal to model a distribution, so
  // that single documented outcome is reproduced deterministically.
  "Data Exfiltration": { "Malware Traffic": 1.0 },
};

// What a false-positive (a truly Normal window the gate still flags) tends to get
// classified as -- DoS/DDoS dominates the real model's predicted-class distribution
// (Chapter 5.1's column totals), so it dominates here too.
const FALSE_POSITIVE_PREDICTION_WEIGHTS: Partial<Record<Exclude<AttackCategory, "Normal">, number>> = {
  "DoS / DDoS": 0.5,
  "Botnet Activity": 0.2,
  "Brute Force": 0.15,
  "Malware Traffic": 0.15,
};

function clip(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function normalizeAnomalyScore(raw: number): number {
  return clip((raw - ANOMALY_SCORE_LOW) / (ANOMALY_SCORE_HIGH - ANOMALY_SCORE_LOW), 0, 1);
}

function riskLevelFor(riskScore: number): RiskLevel {
  if (riskScore >= RISK_HIGH_CUTOFF) return "High";
  if (riskScore >= RISK_LOW_CUTOFF) return "Medium";
  return "Low";
}

function pickPredictedCategory(
  rng: ReturnType<typeof createRng>,
  actualCategory: AttackCategory,
): Exclude<AttackCategory, "Normal"> {
  if (actualCategory === "Normal") {
    const entries = Object.entries(FALSE_POSITIVE_PREDICTION_WEIGHTS) as [Exclude<AttackCategory, "Normal">, number][];
    return weightedChoice(
      rng,
      entries.map(([category]) => category),
      entries.map(([, weight]) => weight),
    );
  }
  const distribution = CONFUSION[actualCategory];
  const entries = Object.entries(distribution) as [Exclude<AttackCategory, "Normal">, number][];
  return weightedChoice(
    rng,
    entries.map(([category]) => category),
    entries.map(([, weight]) => weight),
  );
}

export function buildShapJson(rng: ReturnType<typeof createRng>, category: Exclude<AttackCategory, "Normal">): string {
  const pool = SHAP_FEATURE_POOLS[category];
  const count = Math.min(pool.length, randInt(rng, 5, 8));
  let remaining = randInt(rng, 60, 95) / 100; // top feature's importance, decays from here
  const features: ShapFeature[] = [];
  for (let i = 0; i < count; i++) {
    const value = i === 0 ? remaining : remaining * (0.35 + rng() * 0.35);
    features.push({ feature: pool[i], mean_abs_shap: Math.round(value * 10000) / 10000 });
    remaining = value;
  }
  return JSON.stringify(features);
}

export interface GeneratedAlert {
  alert: AlertOut;
  features: ReturnType<typeof buildFeatureVector>;
}

interface BatchPlan {
  batchId: string;
  sourceFile: string;
  alertCount: number;
  /** Minutes before "now" this batch's alerts start arriving. */
  startMinutesAgo: number;
  /** Seconds between consecutive alerts within this batch (mimics the stream simulator's paced chunks). */
  spacingSeconds: number;
}

// Six synthetic ingest batches spread over the last ~2 hours, each with its own
// pacing -- mirrors how the real stream simulator (Chapter 11 of the Deep-Dive
// report) makes alerts arrive as a real trend over time rather than one instant
// spike, so a timeseries chart built on this data has actual shape to show.
const BATCH_PLANS: readonly Omit<BatchPlan, "batchId">[] = [
  { sourceFile: "panel_demo_traffic.csv", alertCount: 60, startMinutesAgo: 115, spacingSeconds: 45 },
  { sourceFile: "stream_chunk_0827_a.csv", alertCount: 45, startMinutesAgo: 88, spacingSeconds: 20 },
  { sourceFile: "uploaded_traffic_0827.csv", alertCount: 55, startMinutesAgo: 64, spacingSeconds: 35 },
  { sourceFile: "stream_chunk_0827_b.csv", alertCount: 40, startMinutesAgo: 40, spacingSeconds: 15 },
  { sourceFile: "panel_demo_traffic.csv", alertCount: 50, startMinutesAgo: 22, spacingSeconds: 25 },
  { sourceFile: "stream_chunk_0828_morning.csv", alertCount: 35, startMinutesAgo: 6, spacingSeconds: 10 },
];

function makeBatchId(index: number): string {
  return `demo-batch-${String(index + 1).padStart(2, "0")}-${(0x9e3779b9 + index * 2654435761).toString(16).slice(0, 8)}`;
}

/**
 * Generates a full mock alert dataset: realistic in category mix, risk distribution,
 * SHAP presence, and timing, but entirely synthetic -- no real model, real traffic,
 * or real database involved. Deterministic for a given seed so a demo looks the same
 * across reloads.
 */
export function generateMockAlerts(seed = 42): GeneratedAlert[] {
  const rng = createRng(seed);
  const now = Date.now();
  const generated: GeneratedAlert[] = [];
  let nextId = 1;

  const categoryNames = Object.keys(CATEGORY_WEIGHTS) as AttackCategory[];
  const categoryWeightValues = categoryNames.map((name) => CATEGORY_WEIGHTS[name]);

  BATCH_PLANS.forEach((plan, batchIndex) => {
    const batchId = makeBatchId(batchIndex);
    const batchStartMs = now - plan.startMinutesAgo * 60_000;
    let windowStart = randInt(rng, 0, 20);

    for (let i = 0; i < plan.alertCount; i++) {
      const actualCategory = weightedChoice(rng, categoryNames, categoryWeightValues);
      const isAnomaly = rng() < GATE_PASS_RATE[actualCategory];

      let predictedLabel: AttackCategory = "Normal";
      let confidence = 0;
      let topClassifierFeatures: string | null = null;
      let topAnomalyFeatures: string | null = null;

      const rawAnomalyScore = isAnomaly
        ? randInt(rng, Math.round(ANOMALY_THRESHOLD * 1000), 3200) / 1000
        : randInt(rng, 20, Math.round(ANOMALY_THRESHOLD * 1000) - 1) / 1000;
      const normalizedAnomaly = normalizeAnomalyScore(rawAnomalyScore);

      if (isAnomaly) {
        const predicted = pickPredictedCategory(rng, actualCategory);
        predictedLabel = predicted;
        const correct = predicted === actualCategory;
        confidence = correct ? randInt(rng, 8500, 9999) / 10000 : randInt(rng, 4200, 8400) / 10000;
      }

      const riskScore = isAnomaly ? Math.max(normalizedAnomaly, confidence) : normalizedAnomaly;
      const riskLevel = riskLevelFor(riskScore);

      if (isAnomaly && riskLevel !== "Low") {
        const explainCategory = predictedLabel === "Normal" ? "DoS / DDoS" : (predictedLabel as Exclude<AttackCategory, "Normal">);
        topClassifierFeatures = buildShapJson(rng, explainCategory);
        topAnomalyFeatures = buildShapJson(rng, explainCategory);
      }

      const rawLabelPool = RAW_LABELS_BY_CATEGORY[actualCategory];
      const actualLabel = rawLabelPool[randInt(rng, 0, rawLabelPool.length - 1)];

      const windowEnd = windowStart + 9;
      const ingestedAt = new Date(batchStartMs + i * plan.spacingSeconds * 1000);

      const alert: AlertOut = {
        id: nextId++,
        batch_id: batchId,
        window_start: windowStart,
        window_end: windowEnd,
        source_file: plan.sourceFile,
        actual_label: actualLabel,
        actual_category: actualCategory,
        predicted_label: predictedLabel,
        confidence: Math.round(confidence * 1e6) / 1e6,
        anomaly_score: Math.round(rawAnomalyScore * 1e6) / 1e6,
        anomaly_threshold: ANOMALY_THRESHOLD,
        is_anomaly: isAnomaly,
        pipeline_action: isAnomaly ? "Classified and alerted" : "Ignored as normal",
        risk_score: Math.round(riskScore * 1e6) / 1e6,
        risk_level: riskLevel,
        top_classifier_features: topClassifierFeatures,
        top_anomaly_features: topAnomalyFeatures,
        ingested_at: ingestedAt.toISOString(),
      };

      const featureSourceCategory = isAnomaly ? (predictedLabel === "Normal" ? actualCategory : predictedLabel) : actualCategory;
      generated.push({
        alert,
        features: buildFeatureVector(rng, featureSourceCategory),
      });

      windowStart += 5; // stride = 5 (Chapter 8.2 of the Deep-Dive report)
    }
  });

  return generated;
}

export function toAlertDetail(entry: GeneratedAlert): AlertDetailOut {
  return { ...entry.alert, features: entry.features };
}
