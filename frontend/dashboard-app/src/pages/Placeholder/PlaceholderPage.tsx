import { PageHeader } from "../../components/common/PageHeader";
import "./PlaceholderPage.css";

interface PlaceholderPageProps {
  title: string;
  subtitle: string;
  note: string;
}

/** A nav destination that exists in the app shell but isn't built out yet. */
export function PlaceholderPage({ title, subtitle, note }: PlaceholderPageProps) {
  return (
    <section>
      <PageHeader title={title} subtitle={subtitle} />
      <div className="card placeholder-card">
        <div className="empty-state">
          <div className="glyph">&#9676;</div>
          {note}
        </div>
      </div>
    </section>
  );
}
