import { useState } from "react";
import type { TimeseriesPointOut } from "../../types/api";
import { formatClockTime } from "../../utils/format";
import "./RiskTimeseriesChart.css";

const CHART_HEIGHT = 180;
const PLOT_HEIGHT = CHART_HEIGHT - 12;
const BAR_GAP = 2; // surface gap between touching bars
const SEGMENT_GAP = 2; // surface gap between stacked segments within one bar
const MAX_BAR_WIDTH = 22;

type SegmentKey = "low" | "medium" | "high";
const SEGMENT_ORDER: SegmentKey[] = ["low", "medium", "high"];

interface HoverInfo {
  index: number;
  xPercent: number;
}

/**
 * Stacked bar chart of alert volume over time, split by risk level (a fixed
 * three-step status scale, not an open categorical set) -- one bar per
 * timeseries bucket from GET /api/stats/timeseries.
 */
export function RiskTimeseriesChart({ points }: { points: TimeseriesPointOut[] }) {
  const [hover, setHover] = useState<HoverInfo | null>(null);

  const maxTotal = Math.max(1, ...points.map((p) => p.count));
  const n = points.length;
  const chartWidth = Math.max(320, n * (MAX_BAR_WIDTH + BAR_GAP));
  const barWidth = Math.min(MAX_BAR_WIDTH, chartWidth / n - BAR_GAP);

  function segmentPixelHeight(value: number): number {
    return (value / maxTotal) * PLOT_HEIGHT;
  }

  return (
    <div className="ts-chart">
      <div className="ts-chart-inner">
        <svg
          viewBox={`0 0 ${chartWidth} ${CHART_HEIGHT}`}
          width="100%"
          height={CHART_HEIGHT}
          preserveAspectRatio="none"
          role="img"
          aria-label={`Alert volume over time across ${n} buckets, split by risk level`}
        >
          <line x1={0} y1={CHART_HEIGHT - 1} x2={chartWidth} y2={CHART_HEIGHT - 1} className="ts-baseline" />

          {points.map((point, index) => {
            const x = index * (barWidth + BAR_GAP);
            const heights: Record<SegmentKey, number> = {
              low: segmentPixelHeight(point.low),
              medium: segmentPixelHeight(point.medium),
              high: segmentPixelHeight(point.high),
            };
            const topSegment = [...SEGMENT_ORDER].reverse().find((key) => heights[key] > 0);

            let cursorY = CHART_HEIGHT - 1;
            const rects = SEGMENT_ORDER.map((key) => {
              const height = heights[key];
              if (height <= 0) return null;
              cursorY -= height;
              const rect = { key, y: cursorY, height };
              cursorY -= SEGMENT_GAP;
              return rect;
            }).filter((r): r is { key: SegmentKey; y: number; height: number } => r !== null);

            return (
              <g
                key={point.bucket}
                tabIndex={0}
                className="ts-bar-group"
                onMouseEnter={() => setHover({ index, xPercent: (x + barWidth / 2) / chartWidth })}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover({ index, xPercent: (x + barWidth / 2) / chartWidth })}
                onBlur={() => setHover(null)}
              >
                <rect x={x} y={0} width={barWidth} height={CHART_HEIGHT} fill="transparent" />
                {rects.map((r) => (
                  <rect
                    key={r.key}
                    x={x}
                    y={r.y}
                    width={barWidth}
                    height={r.height}
                    rx={r.key === topSegment ? 4 : 0}
                    className={`ts-seg-${r.key}${hover?.index === index ? " ts-seg--hovered" : ""}`}
                  />
                ))}
              </g>
            );
          })}
        </svg>
      </div>

      {hover && points[hover.index] && (
        <div className="ts-tooltip" style={{ left: `${hover.xPercent * 100}%` }}>
          <div className="ts-tooltip-time">{formatClockTime(points[hover.index].bucket)}</div>
          <div className="ts-tooltip-row">
            <span className="ts-key ts-key-high" /> High <b>{points[hover.index].high}</b>
          </div>
          <div className="ts-tooltip-row">
            <span className="ts-key ts-key-medium" /> Medium <b>{points[hover.index].medium}</b>
          </div>
          <div className="ts-tooltip-row">
            <span className="ts-key ts-key-low" /> Low <b>{points[hover.index].low}</b>
          </div>
          <div className="ts-tooltip-row ts-tooltip-total">
            Total <b>{points[hover.index].count}</b>
          </div>
        </div>
      )}
    </div>
  );
}
