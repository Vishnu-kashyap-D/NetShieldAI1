import { CATEGORY_ORDER, UNKNOWN_CATEGORY } from "../../constants/taxonomy";
import { BarList } from "../common/BarList";
import { reliabilityWarning } from "../../constants/reliability";

// Never reordered by count: reordering rows on every refresh makes a list
// impossible to scan, and category identity here comes from the fixed row
// position + label, not from color (this is a single-hue magnitude chart).
export function CategoryDistribution({ counts }: { counts: Record<string, number> }) {
  // "Unknown" only appears once the classifier has actually abstained on something (the option is off by
  // default), so a permanent empty row doesn't clutter the chart.
  const categories = (counts[UNKNOWN_CATEGORY] ?? 0) > 0 ? [...CATEGORY_ORDER, UNKNOWN_CATEGORY] : CATEGORY_ORDER;
  const items = categories.map((category) => ({
    key: category,
    label: category,
    value: counts[category] ?? 0,
    displayValue: String(counts[category] ?? 0),
    flagTitle: reliabilityWarning(category) ?? undefined,
  }));

  // Teal, not violet: this is a security-operations analytics view (threat volume),
  // not a model-intelligence surface -- see the SOC redesign color hierarchy.
  return <BarList items={items} labelWidth="118px" accent="teal" />;
}
