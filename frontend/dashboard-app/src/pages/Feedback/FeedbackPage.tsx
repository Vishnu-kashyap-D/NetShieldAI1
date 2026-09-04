import { Link } from "react-router-dom";
import { useDataProvider } from "../../data/DataModeContext";
import { usePolledAsync } from "../../hooks/usePolledAsync";
import { PageHeader } from "../../components/common/PageHeader";
import { SectionCard } from "../../components/common/SectionCard";
import { AsyncSection } from "../../components/common/AsyncSection";
import { formatFullDateTime } from "../../utils/format";
import "./FeedbackPage.css";

const POLL_MS = 15_000;

/**
 * Global feedback log -- GET /api/feedback (backend/app/routers/feedback.py) returns
 * every submitted correction across all alerts, with no filtering support. This page
 * is that list; per-alert feedback (submission + a filtered view of this same list)
 * lives on the Alert Detail page instead, since that's the only place the backend's
 * one-request-per-alert model makes sense.
 */
export function FeedbackPage() {
  const provider = useDataProvider();
  const feedback = usePolledAsync(() => provider.listFeedback(), [provider], POLL_MS);
  const dataSourceNotice = provider.getDataSourceNotice();

  return (
    <section>
      <PageHeader title="Feedback" subtitle="Analyst-validated corrections submitted across all alerts" />

      {dataSourceNotice && <div className="data-source-notice">{dataSourceNotice}</div>}

      <SectionCard title="Feedback log" subtitle="Every correction submitted, newest first">
        <AsyncSection
          {...feedback}
          isEmpty={(list) => list.length === 0}
          emptyLabel="No feedback submitted yet — open an alert and submit a validated classification."
          loadingLabel="Loading feedback…"
        >
          {(list) => (
            <div className="feedback-log-wrap">
              <table className="feedback-log-table">
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Validated label</th>
                    <th>Analyst</th>
                    <th>Submitted</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((entry) => (
                    <tr key={entry.id}>
                      <td data-label="Alert">
                        <Link to={`/alerts/${entry.alert_id}`} className="feedback-log-alert-link">
                          #{entry.alert_id}
                        </Link>
                      </td>
                      <td data-label="Validated label">{entry.validated_label}</td>
                      <td data-label="Analyst">{entry.analyst ?? "Unknown analyst"}</td>
                      <td data-label="Submitted" className="mono">
                        {formatFullDateTime(entry.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncSection>
      </SectionCard>
    </section>
  );
}
