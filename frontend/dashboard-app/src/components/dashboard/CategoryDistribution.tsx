import { CATEGORY_ORDER } from "../../constants/taxonomy";
import { BarList } from "../common/BarList";

// Never reordered by count: reordering rows on every refresh makes a list
// impossible to scan, and category identity here comes from the fixed row
// position + label, not from color (this is a single-hue magnitude chart).
export function CategoryDistribution({ counts }: { counts: Record<string, number> }) {
  const items = CATEGORY_ORDER.map((category) => ({
    key: category,
    label: category,
    value: counts[category] ?? 0,
    displayValue: String(counts[category] ?? 0),
  }));

  return <BarList items={items} labelWidth="118px" accent="brand" />;
}
