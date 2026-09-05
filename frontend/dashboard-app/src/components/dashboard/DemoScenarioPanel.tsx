import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { AlertOut, FeedbackOut, TrainingRunOut } from "../../types/api";
import type { SimulatedWorkflowEvent } from "../../data/mock/scenario";
import { MockDataProvider } from "../../data/mockProvider";
import { useDataProvider } from "../../data/DataModeContext";
import { RiskBadge } from "../common/RiskBadge";
import "./DemoScenarioPanel.css";

interface ScenarioState {
  trafficReceived: boolean;
  alerts: AlertOut[]; // every alert created this run, oldest first
  explainedIds: Set<number>;
  feedback: FeedbackOut | null;
  retrainRun: TrainingRunOut | null;
}

const EMPTY_STATE: ScenarioState = {
  trafficReceived: false,
  alerts: [],
  explainedIds: new Set(),
  feedback: null,
  retrainRun: null,
};

function applyEvent(prev: ScenarioState, event: SimulatedWorkflowEvent): ScenarioState {
  switch (event.type) {
    case "traffic_state":
      return prev.trafficReceived ? prev : { ...prev, trafficReceived: true };
    case "alert_created":
      // Replaying the same log twice must be a no-op (React StrictMode double-invokes
      // effects in dev, and re-subscribing after a remount always replays from the
      // start), so this dedupes by id instead of blindly appending.
      return prev.alerts.some((a) => a.id === event.alert.id)
        ? prev
        : { ...prev, alerts: [...prev.alerts, event.alert] };
    case "explanation_ready":
      return { ...prev, explainedIds: new Set(prev.explainedIds).add(event.alertId) };
    case "feedback_recorded":
      return { ...prev, feedback: event.feedback };
    case "retrain_status":
      return { ...prev, retrainRun: event.run };
    default:
      return prev;
  }
}

interface DemoScenarioPanelProps {
  /** Lets the Dashboard refresh its own stats/chart/table when the scenario creates a new alert. */
  onWorkflowEvent?: (event: SimulatedWorkflowEvent) => void;
}

/**
 * A deliberate, presenter-controlled walkthrough of the conceptual NetShield workflow
 * (traffic -> detection -> classification -> risk -> alert -> explanation -> analyst
 * review -> feedback -> retraining), built entirely on top of the mock provider's own
 * scenario simulation. This does not run a second simulation engine and does not
 * invoke the real Autoencoder/BiLSTM/SHAP pipeline -- every step shown here is either a
 * real event the mock provider actually emitted, or a real field already present on the
 * mock alert/feedback/training-run object that event carried.
 *
 * The panel subscribes to the scenario on mount (not on button click) so that
 * navigating away to inspect the generated alert -- the intended workflow -- and
 * coming back reconnects to the *same* run already in progress, rather than losing
 * it (the run itself lives on the provider, not this component). Mock-mode only:
 * running this against a real backend would submit a fake analyst correction and
 * trigger a real training run, so it's hidden entirely outside DEMO mode.
 */
export function DemoScenarioPanel({ onWorkflowEvent }: DemoScenarioPanelProps) {
  const provider = useDataProvider();
  const [state, setState] = useState<ScenarioState>(EMPTY_STATE);

  useEffect(() => {
    if (!(provider instanceof MockDataProvider)) return;
    const cancel = provider.subscribeToScenario((event) => {
      onWorkflowEvent?.(event);
      setState((prev) => applyEvent(prev, event));
    });
    return cancel;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider]);

  if (!(provider instanceof MockDataProvider)) return null;
  // Captured as its own const so its narrowed type survives into the start()
  // closure below -- narrowing from the guard above doesn't cross a nested
  // function boundary on its own.
  const mockProvider = provider;

  const hasStarted = state.trafficReceived;
  const isComplete = state.retrainRun !== null && state.retrainRun.status !== "running";
  const isRunning = hasStarted && !isComplete;

  function start() {
    if (isRunning) return; // one run at a time -- no accidental overlap
    setState(EMPTY_STATE);
    mockProvider.startScenario();
  }

  const latestAlert = state.alerts[state.alerts.length - 1] ?? null;
  const latestExplained = latestAlert ? state.explainedIds.has(latestAlert.id) : false;

  return (
    <div className="demo-scenario-panel">
      <div className="demo-scenario-head">
        <span className="badge info demo-scenario-tag">Demo Scenario</span>
        <div>
          <div className="demo-scenario-title">Simulate a suspicious network incident</div>
          <div className="demo-scenario-sub">
            Plays a scripted walkthrough of the NetShield workflow using the mock provider's own simulation — not
            real model output.
          </div>
        </div>
        <button className="btn primary demo-scenario-run" onClick={start} disabled={isRunning}>
          {isRunning ? "Simulation running…" : hasStarted ? "Run again" : "Run Demo Scenario"}
        </button>
      </div>

      {hasStarted && (
        <div className="demo-scenario-body">
          <ol className="demo-scenario-steps">
            <ScenarioStep done={state.trafficReceived}>Traffic received</ScenarioStep>
            <ScenarioStep done={!!latestAlert?.is_anomaly}>Anomaly detected</ScenarioStep>
            <ScenarioStep done={!!latestAlert}>
              {latestAlert ? (
                <>
                  Threat classified as <b>{latestAlert.predicted_label}</b>
                </>
              ) : (
                "Threat classified"
              )}
            </ScenarioStep>
            <ScenarioStep done={!!latestAlert}>
              {latestAlert ? (
                <>
                  Risk calculated: <RiskBadge level={latestAlert.risk_level} />
                </>
              ) : (
                "Risk calculated"
              )}
            </ScenarioStep>
            <ScenarioStep done={!!latestAlert}>
              {latestAlert ? `Alert generated (#${latestAlert.id})` : "Alert generated"}
            </ScenarioStep>
            <ScenarioStep done={latestExplained}>Explanation available (SHAP)</ScenarioStep>
            <li className="demo-scenario-step demo-scenario-step--action">
              {latestAlert && latestExplained ? (
                <Link to={`/alerts/${latestAlert.id}`} className="demo-scenario-link">
                  Investigate alert #{latestAlert.id} →
                </Link>
              ) : (
                <span className="demo-scenario-pending">Analyst investigation (open the alert once ready)</span>
              )}
            </li>
            <ScenarioStep done={!!state.feedback}>
              {state.feedback ? (
                <>
                  Feedback recorded: <b>{state.feedback.validated_label}</b> (simulated analyst confirmation)
                </>
              ) : (
                "Analyst feedback"
              )}
            </ScenarioStep>
            <ScenarioStep done={!!state.retrainRun}>Retraining triggered</ScenarioStep>
            <ScenarioStep done={isComplete}>
              {state.retrainRun && state.retrainRun.status !== "running" ? (
                <>
                  Training {state.retrainRun.status} —{" "}
                  <Link to="/retraining" className="demo-scenario-link">
                    view details →
                  </Link>
                </>
              ) : (
                "Training complete"
              )}
            </ScenarioStep>
          </ol>

          {state.alerts.length > 0 && (
            <div className="demo-scenario-alerts">
              <div className="demo-scenario-alerts-title">Alerts generated this run</div>
              <div className="demo-scenario-alerts-list">
                {state.alerts.map((alert) => (
                  <Link key={alert.id} to={`/alerts/${alert.id}`} className="demo-scenario-alert-chip">
                    #{alert.id} {alert.predicted_label}
                    <RiskBadge level={alert.risk_level} />
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ScenarioStep({ done, children }: { done: boolean; children: ReactNode }) {
  return (
    <li className={`demo-scenario-step${done ? " demo-scenario-step--done" : ""}`}>
      <span className="demo-scenario-step-icon">{done ? "✓" : "○"}</span>
      {children}
    </li>
  );
}
