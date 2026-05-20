import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";
import { ArrowLeft, Filter } from "lucide-react";
import { api, FindingSummary, FindingsPage, ScanDetail as ScanDetailType } from "../api/client";
import DeleteScanButton from "../components/DeleteScanButton";
import SeverityBadge from "../components/SeverityBadge";
import StatusPill from "../components/StatusPill";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#f59e0b",
  LOW: "#0284c7",
  INFO: "#94a3b8",
};

const VULN_TYPES = ["", "SQLI", "XSS", "RCE", "LFI", "RFI", "SSRF", "UPLOAD", "REDIRECT", "WP", "OBJINJ"];
const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function ScanDetail() {
  const nav = useNavigate();
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<ScanDetailType | null>(null);
  const [findings, setFindings] = useState<FindingsPage | null>(null);
  const [severity, setSeverity] = useState("");
  const [vulnType, setVulnType] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!scanId) return;
    try {
      const s = await api.getScan(scanId);
      setScan(s);
      setError(null);
      try {
        const f = await api.getFindings(scanId, {
          ...(severity && { severity }),
          ...(vulnType && { vuln_type: vulnType }),
          limit: "500",
        });
        setFindings(f);
      } catch {
        setFindings({ scan_id: scanId, total: 0, items: [], severity_counts: {}, rule_counts: {} });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Load failed");
    }
  }, [scanId, severity, vulnType]);

  useEffect(() => {
    load();
    const t = setInterval(() => {
      if (scan?.status === "RUNNING" || scan?.status === "QUEUED") load();
    }, 3000);
    return () => clearInterval(t);
  }, [load, scan?.status]);

  const pieData = findings
    ? Object.entries(findings.severity_counts).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <Link to="/" className="inline-flex items-center gap-1 text-sm text-brand-orange font-medium mb-4 hover:underline">
        <ArrowLeft className="w-4 h-4" /> Back to dashboard
      </Link>

      {error && (
        <div className="mb-4 p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm">{error}</div>
      )}

      {scan && (
        <header className="mb-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold text-brand-navy">
                {scan.source_label || scan.plugin_slug}
              </h1>
              <p className="text-muted text-sm mt-1 font-mono">{scan.scan_id}</p>
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              <StatusPill status={scan.status} />
              {scan.status === "FAILED" && scan.error_message && (
                <span className="text-sm text-red-600 max-w-md">{scan.error_message}</span>
              )}
              <span className="text-lg font-bold text-brand-navy">{scan.findings_count} findings</span>
              {scanId && (
                <DeleteScanButton
                  scanId={scanId}
                  onDeleted={() => nav("/")}
                />
              )}
            </div>
          </div>
          {(scan.status === "RUNNING" || scan.status === "QUEUED") && (
            <ProgressPanel
              stage={scan.stage}
              detail={scan.progress}
              pct={scan.progress_pct}
              queued={scan.status === "QUEUED"}
            />
          )}
        </header>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="lg:col-span-1 bg-card rounded-2xl border border-border p-6 shadow-sm">
          <h2 className="font-semibold text-brand-navy mb-4 flex items-center gap-2">
            <Filter className="w-4 h-4" /> Filters
          </h2>
          <div className="space-y-4">
            <label className="block text-sm">
              <span className="font-medium text-slate-700">Severity</span>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-border"
              >
                <option value="">All severities</option>
                {SEVERITIES.filter(Boolean).map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label className="block text-sm">
              <span className="font-medium text-slate-700">Vulnerability type</span>
              <select
                value={vulnType}
                onChange={(e) => setVulnType(e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-border"
              >
                <option value="">All types</option>
                {VULN_TYPES.filter(Boolean).map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {pieData.length > 0 && (
            <div className="mt-8 pt-6 border-t border-border">
              <h3 className="text-sm font-semibold text-brand-navy mb-3">Severity breakdown</h3>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart margin={{ top: 8, right: 8, bottom: 8, left: 8 }}>
                    <Pie
                      data={pieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="45%"
                      innerRadius={42}
                      outerRadius={70}
                      paddingAngle={4}
                      stroke="#ffffff"
                      strokeWidth={2}
                      labelLine={false}
                      label={({ percent }) =>
                        percent && percent >= 0.06 ? `${Math.round(percent * 100)}%` : ""
                      }
                    >
                      {pieData.map((d) => (
                        <Cell key={d.name} fill={SEV_COLORS[d.name] ?? "#64748b"} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        borderRadius: 8,
                        border: "1px solid #e2e8f0",
                        fontSize: 12,
                      }}
                    />
                    <Legend
                      verticalAlign="bottom"
                      iconType="circle"
                      iconSize={8}
                      wrapperStyle={{ paddingTop: 12, fontSize: 12 }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>

        <div className="lg:col-span-2 bg-card rounded-2xl border border-border shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-border">
            <h2 className="font-semibold text-brand-navy">
              Vulnerabilities {findings ? `(${findings.total})` : ""}
            </h2>
          </div>
          {!findings || findings.items.length === 0 ? (
            <p className="p-8 text-center text-muted text-sm">
              {scan?.status === "RUNNING" || scan?.status === "QUEUED"
                ? "Scan in progress…"
                : "No findings match your filters."}
            </p>
          ) : (
            <ul className="divide-y divide-border max-h-[600px] overflow-auto">
              {findings.items.map((f) => (
                <FindingRow key={f.finding_id} f={f} />
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

const STAGE_LABELS: Record<string, string> = {
  queued: "Waiting in queue",
  starting: "Starting scan worker",
  ingest: "Reading plugin files",
  snapshot: "Saving repository snapshot",
  parse: "Parsing source files",
  graph: "Building security graph",
  analysis: "Running security rules",
  reporting: "Writing report",
  complete: "Complete",
  failed: "Failed",
};

function ProgressPanel({
  stage,
  detail,
  pct,
  queued,
}: {
  stage: string | null | undefined;
  detail: string | null | undefined;
  pct: number | null | undefined;
  queued: boolean;
}) {
  const label = (stage && STAGE_LABELS[stage]) || (queued ? "Queued" : "Running");
  const value = Math.max(0, Math.min(100, pct ?? 0));
  return (
    <div className="mt-5 bg-card border border-border rounded-2xl p-5 shadow-sm">
      <div className="flex items-baseline justify-between gap-4 mb-2">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-orange opacity-60" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-orange" />
          </span>
          <span className="text-sm font-semibold text-brand-navy">{label}</span>
        </div>
        <span className="text-sm font-mono text-brand-navy tabular-nums">{value.toFixed(0)}%</span>
      </div>
      <div className="h-2 w-full rounded-full bg-slate-100 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-brand-orange to-brand-orange-hover transition-all duration-500 ease-out"
          style={{ width: `${value}%` }}
        />
      </div>
      {detail && (
        <p className="mt-2 text-xs text-muted font-mono truncate" title={detail}>
          {detail}
        </p>
      )}
    </div>
  );
}

function FindingRow({ f }: { f: FindingSummary }) {
  return (
    <li className="px-6 py-4 hover:bg-slate-50 transition">
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <SeverityBadge severity={f.severity} />
        <span className="text-xs font-mono text-muted">{f.rule_id}</span>
        <span className="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-600">{f.vuln_type}</span>
      </div>
      <p className="font-medium text-slate-800">{f.title}</p>
      {f.file_path && (
        <p className="text-sm text-muted mt-1">
          {f.file_path}
          {f.start_line != null ? `:${f.start_line}` : ""}
        </p>
      )}
      {f.confidence_score != null && (
        <p className="text-xs text-muted mt-1">Confidence: {(f.confidence_score * 100).toFixed(0)}%</p>
      )}
    </li>
  );
}
