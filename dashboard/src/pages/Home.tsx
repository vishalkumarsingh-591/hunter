import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ArrowRight, FileWarning, ShieldCheck, AlertTriangle, Activity, Search } from "lucide-react";
import { api, ScanStats, ScanSummary } from "../api/client";
import DeleteScanButton from "../components/DeleteScanButton";
import StatusPill from "../components/StatusPill";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#f59e0b",
  LOW: "#0284c7",
  INFO: "#94a3b8",
};

const VULN_PALETTE = [
  "#f57c20",
  "#0ea5e9",
  "#22c55e",
  "#a855f7",
  "#ec4899",
  "#facc15",
  "#14b8a6",
  "#f43f5e",
  "#6366f1",
  "#84cc16",
  "#06b6d4",
  "#eab308",
];

export default function Home() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");

  const load = useCallback((silent = false) => {
    if (!silent) setLoading(true);
    Promise.all([api.listScans(), api.stats()])
      .then(([s, st]) => {
        setScans(s);
        setStats(st);
        setError(null);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load"))
      .finally(() => {
        if (!silent) setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const hasInflight = scans.some((s) => s.status === "RUNNING" || s.status === "QUEUED");
  useEffect(() => {
    if (!hasInflight) return;
    const t = setInterval(() => load(true), 3000);
    return () => clearInterval(t);
  }, [hasInflight, load]);

  const severityData = useMemo(
    () => Object.entries(stats?.by_severity ?? {}).map(([name, value]) => ({ name, value })),
    [stats],
  );
  const vulnData = useMemo(
    () =>
      Object.entries(stats?.by_vuln_type ?? {})
        .sort((a, b) => b[1] - a[1])
        .map(([name, value]) => ({ name, value })),
    [stats],
  );
  const totalVulns = vulnData.reduce((acc, d) => acc + d.value, 0);

  const filteredScans = scans.filter((s) => {
    if (!query.trim()) return true;
    const q = query.toLowerCase();
    return (
      (s.source_label ?? "").toLowerCase().includes(q) ||
      s.plugin_slug.toLowerCase().includes(q) ||
      s.scan_id.toLowerCase().includes(q) ||
      s.status.toLowerCase().includes(q)
    );
  });

  return (
    <div className="p-8 max-w-7xl mx-auto theme-transition">
      <header className="mb-8 flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold text-fg tracking-tight">Security Dashboard</h1>
          <p className="text-muted mt-1.5">
            WordPress plugin static analysis — aggregate findings across all scans
          </p>
        </div>
        <Link
          to="/scan/new"
          className="inline-flex items-center gap-2 px-5 py-3 rounded-xl bg-brand-orange text-white font-medium shadow-md shadow-brand-orange/25 hover:bg-brand-orange-hover hover:-translate-y-0.5 transition-all"
        >
          New scan <ArrowRight className="w-4 h-4" />
        </Link>
      </header>

      {error && (
        <div className="mb-6 p-4 rounded-xl bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 text-red-800 dark:text-red-300 text-sm">
          {error}. Start the API:{" "}
          <code className="bg-red-100 dark:bg-red-500/20 px-1 rounded">
            uvicorn hunter.api.main:app
          </code>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Total scans"
          value={stats?.total_scans ?? scans.length}
          icon={Activity}
          accent="text-brand-navy dark:text-sky-300"
        />
        <StatCard
          label="Critical"
          value={stats?.by_severity?.CRITICAL ?? 0}
          icon={AlertTriangle}
          accent="text-red-600 dark:text-red-400"
        />
        <StatCard
          label="High"
          value={stats?.by_severity?.HIGH ?? 0}
          icon={AlertTriangle}
          accent="text-orange-600 dark:text-orange-400"
        />
        <StatCard
          label="Vuln types"
          value={Object.keys(stats?.by_vuln_type ?? {}).length}
          icon={ShieldCheck}
          accent="text-emerald-600 dark:text-emerald-400"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <ChartCard title="Findings by severity" subtitle={`${severityData.reduce((a, d) => a + d.value, 0)} total`}>
          {severityData.length === 0 ? (
            <EmptyChart message="No findings yet. Run your first scan to see the breakdown." />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={severityData} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 12, fill: "var(--text-muted)" }}
                  axisLine={{ stroke: "var(--surface-border)" }}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 12, fill: "var(--text-muted)" }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  cursor={{ fill: "var(--color-brand-orange-soft)", opacity: 0.4 }}
                  contentStyle={{
                    background: "var(--tooltip-bg)",
                    border: "1px solid var(--tooltip-border)",
                    borderRadius: 8,
                    fontSize: 12,
                    color: "var(--text-primary)",
                  }}
                />
                <Bar dataKey="value" radius={[8, 8, 0, 0]} animationDuration={650}>
                  {severityData.map((d) => (
                    <Cell key={d.name} fill={SEV_COLORS[d.name] ?? "#64748b"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="By vulnerability type" subtitle={`${totalVulns} findings · ${vulnData.length} types`}>
          {vulnData.length === 0 ? (
            <EmptyChart message="Vulnerability type breakdown will appear after your first scan." />
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 items-center">
              <div className="h-[240px] relative">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={vulnData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={56}
                      outerRadius={92}
                      paddingAngle={3}
                      stroke="var(--surface-card)"
                      strokeWidth={2}
                      animationDuration={700}
                    >
                      {vulnData.map((d, i) => (
                        <Cell key={d.name} fill={VULN_PALETTE[i % VULN_PALETTE.length]} />
                      ))}
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
                        `${value} (${((value / Math.max(1, totalVulns)) * 100).toFixed(1)}%)`,
                        name,
                      ]}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-2xl font-bold text-fg tabular-nums">{totalVulns}</span>
                  <span className="text-[11px] uppercase tracking-wider text-muted">findings</span>
                </div>
              </div>
              <ul className="space-y-1.5 max-h-[240px] overflow-auto pr-1">
                {vulnData.map((d, i) => {
                  const pct = totalVulns ? (d.value / totalVulns) * 100 : 0;
                  return (
                    <li
                      key={d.name}
                      className="flex items-center justify-between gap-3 text-sm py-1.5 px-2 rounded-lg hover:bg-surface transition-colors"
                    >
                      <span className="flex items-center gap-2 min-w-0">
                        <span
                          className="w-2.5 h-2.5 rounded-full shrink-0"
                          style={{ background: VULN_PALETTE[i % VULN_PALETTE.length] }}
                        />
                        <span className="font-medium text-fg truncate">{d.name}</span>
                      </span>
                      <span className="flex items-center gap-2 tabular-nums">
                        <span className="text-muted text-xs">{pct.toFixed(0)}%</span>
                        <span className="font-semibold text-fg w-7 text-right">{d.value}</span>
                      </span>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </ChartCard>
      </div>

      <div className="bg-card rounded-2xl border border-border shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-border flex items-center justify-between gap-3 flex-wrap">
          <h2 className="font-semibold text-fg flex items-center gap-2">
            <FileWarning className="w-4 h-4 text-brand-orange" />
            Recent scans
            {scans.length > 0 && (
              <span className="ml-1 text-xs font-medium px-2 py-0.5 rounded-full bg-brand-orange-soft text-brand-orange">
                {scans.length}
              </span>
            )}
          </h2>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by name, status, id…"
              className="pl-9 pr-4 py-2 rounded-lg border border-border bg-card text-fg text-sm outline-none focus:ring-2 focus:ring-brand-orange/30 focus:border-brand-orange w-64"
            />
          </div>
        </div>
        {loading ? (
          <p className="p-8 text-center text-muted text-sm">Loading…</p>
        ) : filteredScans.length === 0 ? (
          <p className="p-8 text-center text-muted text-sm">
            {scans.length === 0 ? "No scans yet." : "No scans match that filter."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-surface/60 text-left text-muted">
                <tr>
                  <th className="px-6 py-3 font-medium">Source</th>
                  <th className="px-6 py-3 font-medium">Plugin</th>
                  <th className="px-6 py-3 font-medium">Status</th>
                  <th className="px-6 py-3 font-medium">Findings</th>
                  <th className="px-6 py-3 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((s) => {
                  const inflight = s.status === "RUNNING" || s.status === "QUEUED";
                  const pct = Math.max(0, Math.min(100, s.progress_pct ?? 0));
                  return (
                    <tr
                      key={s.scan_id}
                      className="border-t border-border hover:bg-brand-orange-soft/40 dark:hover:bg-white/[0.02] transition-colors"
                    >
                      <td className="px-6 py-4 capitalize text-muted">{s.source_type}</td>
                      <td className="px-6 py-4 font-medium text-fg">
                        {s.source_label || s.plugin_slug}
                      </td>
                      <td className="px-6 py-4 min-w-[280px]">
                        <div className="flex items-center gap-2">
                          <StatusPill status={s.status} />
                          {inflight && (
                            <span className="text-xs font-mono text-fg tabular-nums">
                              {pct.toFixed(0)}%
                            </span>
                          )}
                        </div>
                        {inflight && (
                          <div className="mt-1.5 space-y-1">
                            <div className="h-1.5 w-full max-w-[240px] rounded-full bg-surface overflow-hidden border border-border">
                              <div
                                className="h-full bg-gradient-to-r from-brand-orange to-brand-orange-hover transition-all duration-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                            {s.progress && (
                              <p
                                className="text-[11px] text-muted truncate max-w-[280px]"
                                title={s.progress}
                              >
                                {s.progress}
                              </p>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 font-semibold text-fg tabular-nums">
                        {s.findings_count}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="inline-flex items-center gap-2 justify-end">
                          <Link
                            to={`/scan/${s.scan_id}`}
                            className="text-brand-orange font-medium hover:underline"
                          >
                            View
                          </Link>
                          <DeleteScanButton
                            scanId={s.scan_id}
                            variant="icon"
                            onDeleted={() => load()}
                          />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  accent = "text-fg",
  icon: Icon,
}: {
  label: string;
  value: number;
  accent?: string;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div className="card-hover relative overflow-hidden bg-card rounded-2xl border border-border p-5 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold text-muted uppercase tracking-wider">{label}</p>
          <p className={`text-3xl font-bold mt-2 tabular-nums ${accent}`}>{value}</p>
        </div>
        <div className="w-9 h-9 rounded-xl bg-brand-orange-soft text-brand-orange flex items-center justify-center">
          <Icon className="w-4 h-4" />
        </div>
      </div>
    </div>
  );
}

function ChartCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-card rounded-2xl border border-border p-6 shadow-sm">
      <div className="flex items-baseline justify-between mb-4">
        <h2 className="font-semibold text-fg">{title}</h2>
        {subtitle && <span className="text-xs text-muted">{subtitle}</span>}
      </div>
      {children}
    </div>
  );
}

function EmptyChart({ message }: { message: string }) {
  return (
    <div className="h-[240px] flex items-center justify-center">
      <p className="text-muted text-sm text-center max-w-[260px]">{message}</p>
    </div>
  );
}
