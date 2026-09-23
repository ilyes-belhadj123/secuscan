import type { ReactNode } from "react";
import {
  Bar, BarChart, CartesianGrid, Cell, LabelList, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import type { HistoryPoint, Severity } from "../api";
import { SEVERITIES, SEVERITY_ICON, SEVERITY_LABEL, formatDate } from "../labels";

const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
};

const axisTick = { fill: "var(--text-2)", fontSize: 12.5 };

function TooltipBox({ children }: { children: ReactNode }) {
  return <div className="chart-tooltip">{children}</div>;
}

/** Barres horizontales par sévérité — couleur de statut + icône + libellé, valeur en étiquette directe. */
export function SeverityChart({
  bySeverity,
  onSelect,
}: {
  bySeverity: Record<Severity, number>;
  onSelect?: (s: Severity) => void;
}) {
  const data = SEVERITIES.map((s) => ({
    key: s,
    label: `${SEVERITY_ICON[s]}  ${SEVERITY_LABEL[s]}`,
    value: bySeverity[s] ?? 0,
  }));
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 40, bottom: 4, left: 4 }} barCategoryGap={10}>
        <XAxis type="number" hide allowDecimals={false} />
        <YAxis type="category" dataKey="label" width={96} tick={axisTick} axisLine={{ stroke: "var(--axis)" }} tickLine={false} />
        <Tooltip
          cursor={{ fill: "var(--surface-2)" }}
          content={({ active, payload }) =>
            active && payload?.length ? (
              <TooltipBox>
                <strong>{SEVERITY_LABEL[payload[0].payload.key as Severity]}</strong> : {payload[0].value} alerte(s)
                <div className="muted small">Cliquer pour filtrer la liste</div>
              </TooltipBox>
            ) : null
          }
        />
        <Bar
          dataKey="value"
          radius={[0, 4, 4, 0]}
          maxBarSize={30}
          style={{ cursor: onSelect ? "pointer" : undefined }}
          onClick={(d: { key?: Severity }) => d.key && onSelect?.(d.key)}
          isAnimationActive={false}
        >
          {data.map((d) => (
            <Cell key={d.key} fill={SEV_COLOR[d.key]} />
          ))}
          <LabelList dataKey="value" position="right" fill="var(--text)" fontSize={13} fontWeight={650} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Une seule série : une seule teinte, pas de légende, valeurs en étiquettes directes. */
export function OwaspChart({ byOwasp }: { byOwasp: Record<string, number> }) {
  const data = Object.entries(byOwasp).map(([label, value]) => ({ label, value }));
  return (
    <ResponsiveContainer width="100%" height={Math.max(120, data.length * 38)}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 40, bottom: 0, left: 4 }} barCategoryGap={8}>
        <XAxis type="number" hide allowDecimals={false} />
        <YAxis type="category" dataKey="label" width={430} tick={axisTick} axisLine={{ stroke: "var(--axis)" }} tickLine={false} />
        <Tooltip
          cursor={{ fill: "var(--surface-2)" }}
          content={({ active, payload }) =>
            active && payload?.length ? (
              <TooltipBox>
                <strong>{payload[0].payload.label}</strong>
                <div>{payload[0].value} alerte(s) ouverte(s)</div>
              </TooltipBox>
            ) : null
          }
        />
        <Bar dataKey="value" fill="var(--series-1)" radius={[0, 4, 4, 0]} maxBarSize={24} isAnimationActive={false}>
          <LabelList dataKey="value" position="right" fill="var(--text)" fontSize={13} fontWeight={650} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function ScoreHistoryChart({ points }: { points: HistoryPoint[] }) {
  const data = points.map((p, i) => ({ ...p, idx: i + 1 }));
  return (
    <div>
      <div className="small secondary" style={{ fontWeight: 600, marginBottom: 4 }}>Évolution du score</div>
      <ResponsiveContainer width="100%" height={140}>
        <LineChart data={data} margin={{ top: 8, right: 16, bottom: 0, left: -20 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="idx" tick={axisTick} axisLine={{ stroke: "var(--axis)" }} tickLine={false} tickFormatter={(v) => `#${v}`} />
          <YAxis domain={[0, 100]} ticks={[0, 50, 100]} tick={axisTick} axisLine={false} tickLine={false} />
          <Tooltip
            cursor={{ stroke: "var(--axis)" }}
            content={({ active, payload }) =>
              active && payload?.length ? (
                <TooltipBox>
                  <strong>{payload[0].value}/100</strong>
                  <div className="muted small">{formatDate(payload[0].payload.created_at)} · {payload[0].payload.total} alertes</div>
                </TooltipBox>
              ) : null
            }
          />
          <Line
            type="monotone"
            dataKey="score"
            stroke="var(--series-1)"
            strokeWidth={2}
            dot={{ r: 4, fill: "var(--series-1)", stroke: "var(--surface)", strokeWidth: 2 }}
            activeDot={{ r: 6, stroke: "var(--surface)", strokeWidth: 2 }}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
