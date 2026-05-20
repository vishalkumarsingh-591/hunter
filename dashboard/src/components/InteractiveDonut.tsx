import { useMemo, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Sector, Tooltip } from "recharts";

export type DonutSlice = { name: string; value: number };

type Props = {
  data: DonutSlice[];
  colors: string[] | ((name: string, index: number) => string);
  /** Currently-applied filter; matching slice is highlighted. Empty string = no filter. */
  selected?: string;
  /** Called when a slice is clicked; emits the slice name, or "" if user clicked the active slice (to clear). */
  onSelect?: (name: string) => void;
  /** Center label fallback when nothing is hovered or selected. */
  centerLabel?: string;
  /** Max items to render as cells; the rest go into an "Other" bucket. */
  maxSlices?: number;
  /** Height in px. */
  height?: number;
};

const ACTIVE_OUTSET = 6;

export default function InteractiveDonut({
  data,
  colors,
  selected = "",
  onSelect,
  centerLabel = "findings",
  maxSlices = 10,
  height = 240,
}: Props) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const { slices, total } = useMemo(() => {
    const sorted = [...data].sort((a, b) => b.value - a.value);
    if (sorted.length <= maxSlices) {
      return { slices: sorted, total: sorted.reduce((a, d) => a + d.value, 0) };
    }
    const head = sorted.slice(0, maxSlices - 1);
    const tailSum = sorted.slice(maxSlices - 1).reduce((a, d) => a + d.value, 0);
    const combined = [...head, { name: "Other", value: tailSum }];
    return { slices: combined, total: combined.reduce((a, d) => a + d.value, 0) };
  }, [data, maxSlices]);

  const getColor = (name: string, idx: number): string => {
    if (typeof colors === "function") return colors(name, idx);
    return colors[idx % colors.length];
  };

  const activeIdx =
    hoverIdx ??
    (selected ? slices.findIndex((s) => s.name === selected) : -1);
  const activeSlice = activeIdx >= 0 ? slices[activeIdx] : null;
  const activePct = activeSlice && total > 0 ? (activeSlice.value / total) * 100 : 0;

  const showPct = activeSlice ? activePct : null;
  const showSecondary = activeSlice ? activeSlice.name : centerLabel;

  return (
    <div className="relative w-full" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={slices}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={62}
            outerRadius={92}
            paddingAngle={slices.length > 1 ? 3 : 0}
            stroke="var(--surface-card)"
            strokeWidth={2}
            animationDuration={700}
            activeIndex={activeIdx >= 0 ? activeIdx : undefined}
            activeShape={renderActiveShape}
            onMouseLeave={() => setHoverIdx(null)}
          >
            {slices.map((d, i) => {
              const isSelected = selected && d.name === selected;
              return (
                <Cell
                  key={d.name}
                  fill={getColor(d.name, i)}
                  opacity={
                    selected && !isSelected && hoverIdx === null ? 0.5 : 1
                  }
                  onMouseEnter={() => setHoverIdx(i)}
                  onClick={() => {
                    if (!onSelect) return;
                    onSelect(d.name === selected ? "" : d.name);
                  }}
                  style={{ cursor: onSelect ? "pointer" : "default", outline: "none" }}
                />
              );
            })}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "var(--tooltip-bg)",
              border: "1px solid var(--tooltip-border)",
              borderRadius: 8,
              fontSize: 12,
              color: "var(--text-primary)",
            }}
            formatter={(value: number, name: string) => [
              `${value} (${total ? ((value / total) * 100).toFixed(1) : 0}%)`,
              name,
            ]}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
        <span className="text-2xl font-bold text-fg tabular-nums">
          {activeSlice ? activeSlice.value : total}
        </span>
        {showPct != null ? (
          <span className="text-[11px] font-semibold uppercase tracking-wider text-brand-orange">
            {showPct.toFixed(1)}%
          </span>
        ) : (
          <span className="text-[11px] uppercase tracking-wider text-muted">
            {centerLabel}
          </span>
        )}
        <span className="text-[11px] mt-0.5 max-w-[110px] truncate text-muted">
          {showSecondary !== centerLabel ? showSecondary : ""}
        </span>
      </div>
    </div>
  );
}

type LegendProps = {
  data: DonutSlice[];
  colors: string[] | ((name: string, index: number) => string);
  selected?: string;
  onSelect?: (name: string) => void;
};

export function DonutLegend({ data, colors, selected = "", onSelect }: LegendProps) {
  const total = data.reduce((a, d) => a + d.value, 0);
  const getColor = (name: string, idx: number): string =>
    typeof colors === "function" ? colors(name, idx) : colors[idx % colors.length];
  return (
    <ul className="space-y-1.5 max-h-[260px] overflow-auto pr-1">
      {data.map((d, i) => {
        const pct = total ? (d.value / total) * 100 : 0;
        const isSelected = selected && d.name === selected;
        return (
          <li key={d.name}>
            <button
              type="button"
              onClick={() => onSelect?.(d.name === selected ? "" : d.name)}
              className={`w-full flex items-center justify-between gap-3 text-sm py-1.5 px-2 rounded-lg transition-colors ${
                isSelected
                  ? "bg-brand-orange-soft ring-1 ring-brand-orange/40"
                  : "hover:bg-surface"
              } ${selected && !isSelected ? "opacity-60 hover:opacity-100" : ""}`}
              aria-pressed={isSelected ? true : false}
            >
              <span className="flex items-center gap-2 min-w-0">
                <span
                  className="w-2.5 h-2.5 rounded-full shrink-0"
                  style={{ background: getColor(d.name, i) }}
                />
                <span className="font-medium text-fg truncate text-left">{d.name}</span>
              </span>
              <span className="flex items-center gap-2 tabular-nums">
                <span className="text-muted text-xs">{pct.toFixed(0)}%</span>
                <span className="font-semibold text-fg w-7 text-right">{d.value}</span>
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

// Recharts active shape — pops the slice outward and adds a subtle outer ring.
function renderActiveShape(props: unknown) {
  const p = props as {
    cx: number;
    cy: number;
    innerRadius: number;
    outerRadius: number;
    startAngle: number;
    endAngle: number;
    fill: string;
  };
  return (
    <g>
      <Sector
        cx={p.cx}
        cy={p.cy}
        innerRadius={p.innerRadius}
        outerRadius={p.outerRadius + ACTIVE_OUTSET}
        startAngle={p.startAngle}
        endAngle={p.endAngle}
        fill={p.fill}
      />
      <Sector
        cx={p.cx}
        cy={p.cy}
        innerRadius={p.outerRadius + ACTIVE_OUTSET + 2}
        outerRadius={p.outerRadius + ACTIVE_OUTSET + 4}
        startAngle={p.startAngle}
        endAngle={p.endAngle}
        fill={p.fill}
        opacity={0.35}
      />
    </g>
  );
}
