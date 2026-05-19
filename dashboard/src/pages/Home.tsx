import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { ArrowRight, FileWarning } from "lucide-react";
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

export default function Home() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

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

  // Keep the list fresh while any scan is in flight so progress bars animate live.
  const hasInflight = scans.some((s) => s.status === "RUNNING" || s.status === "QUEUED");
  useEffect(() => {
    if (!hasInflight) return;
    const t = setInterval(() => load(true), 3000);
    return () => clearInterval(t);
  }, [hasInflight, load]);

  const chartData = stats
    ? Object.entries(stats.by_severity).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <header className="mb-8">
        <h1 className="text-2xl font-bold text-brand-navy">Security Dashboard</h1>
        <p className="text-muted mt-1">WordPress plugin static analysis — findings across all scans</p>
      </header>

      {error && (
        <div className="mb-6 p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">
          {error}. Start the API: <code className="bg-red-100 px-1 rounded">uvicorn hunter.api.main:app --reload</code>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Total scans" value={stats?.total_scans ?? scans.length} />
        <StatCard
          label="Critical"
          value={stats?.by_severity?.CRITICAL ?? 0}
          accent="text-red-600"
        />
        <StatCard label="High" value={stats?.by_severity?.HIGH ?? 0} accent="text-orange-600" />
        <StatCard label="Vuln types" value={Object.keys(stats?.by_vuln_type ?? {}).length} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="bg-card rounded-2xl border border-border p-6 shadow-sm">
          <h2 className="font-semibold text-brand-navy mb-4">Findings by severity</h2>
          {chartData.length === 0 ? (
            <p className="text-muted text-sm py-12 text-center">No findings yet. Run your first scan.</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={chartData}>
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {chartData.map((d) => (
                    <Cell key={d.name} fill={SEV_COLORS[d.name] ?? "#64748b"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
        <div className="bg-card rounded-2xl border border-border p-6 shadow-sm">
          <h2 className="font-semibold text-brand-navy mb-4">By vulnerability type</h2>
          <ul className="space-y-2 max-h-[220px] overflow-auto">
            {Object.entries(stats?.by_vuln_type ?? {})
              .sort((a, b) => b[1] - a[1])
              .map(([type, count]) => (
                <li key={type} className="flex justify-between text-sm py-1.5 border-b border-border last:border-0">
                  <span className="font-medium text-slate-700">{type}</span>
                  <span className="text-brand-orange font-semibold">{count}</span>
                </li>
              ))}
            {!stats?.by_vuln_type || Object.keys(stats.by_vuln_type).length === 0 ? (
              <li className="text-muted text-sm py-8 text-center">—</li>
            ) : null}
          </ul>
        </div>
      </div>

      <div className="bg-card rounded-2xl border border-border shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-border flex items-center justify-between">
          <h2 className="font-semibold text-brand-navy flex items-center gap-2">
            <FileWarning className="w-4 h-4 text-brand-orange" />
            Recent scans
          </h2>
          <Link
            to="/scan/new"
            className="text-sm font-medium text-brand-orange hover:text-brand-orange-hover flex items-center gap-1"
          >
            New scan <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
        {loading ? (
          <p className="p-8 text-center text-muted text-sm">Loading…</p>
        ) : scans.length === 0 ? (
          <p className="p-8 text-center text-muted text-sm">No scans yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-muted">
              <tr>
                <th className="px-6 py-3 font-medium">Source</th>
                <th className="px-6 py-3 font-medium">Plugin</th>
                <th className="px-6 py-3 font-medium">Status</th>
                <th className="px-6 py-3 font-medium">Findings</th>
                <th className="px-6 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => {
                const inflight = s.status === "RUNNING" || s.status === "QUEUED";
                const pct = Math.max(0, Math.min(100, s.progress_pct ?? 0));
                return (
                  <tr key={s.scan_id} className="border-t border-border hover:bg-brand-orange-soft/40 transition-colors">
                    <td className="px-6 py-4 capitalize text-slate-600">{s.source_type}</td>
                    <td className="px-6 py-4 font-medium text-slate-800">
                      {s.source_label || s.plugin_slug}
                    </td>
                    <td className="px-6 py-4 min-w-[260px]">
                      <div className="flex items-center gap-2">
                        <StatusPill status={s.status} />
                        {inflight && (
                          <span className="text-xs font-mono text-brand-navy tabular-nums">
                            {pct.toFixed(0)}%
                          </span>
                        )}
                      </div>
                      {inflight && (
                        <div className="mt-1.5 space-y-1">
                          <div className="h-1.5 w-full max-w-[220px] rounded-full bg-slate-100 overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-brand-orange to-brand-orange-hover transition-all duration-500"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          {s.progress && (
                            <p className="text-[11px] text-muted truncate max-w-[260px]" title={s.progress}>
                              {s.progress}
                            </p>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4 font-semibold text-brand-navy">{s.findings_count}</td>
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
        )}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  accent = "text-brand-navy",
}: {
  label: string;
  value: number;
  accent?: string;
}) {
  return (
    <div className="bg-card rounded-2xl border border-border p-5 shadow-sm">
      <p className="text-xs font-medium text-muted uppercase tracking-wider">{label}</p>
      <p className={`text-3xl font-bold mt-2 ${accent}`}>{value}</p>
    </div>
  );
}
