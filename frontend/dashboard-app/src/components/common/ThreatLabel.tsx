import { UNKNOWN_CATEGORY } from "../../constants/taxonomy";
import { UNKNOWN_EXPLANATION, UNRELIABLE_CATEGORIES } from "../../constants/reliability";
import "./ThreatLabel.css";

/**
 * A predicted category, with an inline flag wherever that category isn't reliable. Use this instead of
 * printing `predicted_label` directly so the warning can never be missing from one screen.
 */
export function ThreatLabel({ label }: { label: string }) {
  const unreliable = UNRELIABLE_CATEGORIES[label];
  const isUnknown = label === UNKNOWN_CATEGORY;

  return (
    <>
      {label}
      {unreliable && (
        <span className="threat-flag threat-flag--warn" title={unreliable} tabIndex={0} aria-label={`${label}: ${unreliable}`}>
          unreliable
        </span>
      )}
      {isUnknown && (
        <span className="threat-flag threat-flag--info" title={UNKNOWN_EXPLANATION} tabIndex={0} aria-label={UNKNOWN_EXPLANATION}>
          unclassified
        </span>
      )}
    </>
  );
}
