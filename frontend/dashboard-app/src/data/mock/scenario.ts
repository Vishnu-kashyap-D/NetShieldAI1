import type { AlertOut, FeedbackOut, TrainingRunOut } from "../../types/api";

/**
 * One step of the scripted mock workflow (see MockDataProvider.startScenario /
 * subscribeToScenario).
 * Every event is clearly a *simulation* artifact -- none of it is produced by the real
 * Autoencoder/BiLSTM/SHAP pipeline, and nothing here should be presented to a user as
 * if it were live model output.
 */
export type SimulatedWorkflowEvent =
  | { type: "traffic_state"; state: "normal" | "suspicious"; label: string }
  | { type: "alert_created"; alert: AlertOut }
  | { type: "explanation_ready"; alertId: number }
  | { type: "feedback_recorded"; feedback: FeedbackOut }
  | { type: "retrain_status"; run: TrainingRunOut };
