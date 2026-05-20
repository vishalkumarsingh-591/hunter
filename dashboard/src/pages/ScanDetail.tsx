import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Filter, FileSearch, ShieldAlert, Bug } from "lucide-react";
import { api, FindingSummary, FindingsPage, ScanDetail as ScanDetailType } from "../api/client";
import DeleteScanButton from "../components/DeleteScanButton";
import DownloadReportButton from "../components/DownloadReportButton";
import InteractiveDonut, { DonutLegend } from "../components/InteractiveDonut";
import SeverityBadge from "../components/SeverityBadge";
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
        setFindings({
          scan_id: scanId,
          total: 0,
          items: [],
          severity_counts: {},
          rule_counts: {},
          vuln_type_counts: {},
        });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Load failed");
    }
  }, [scanId, severity, vulnType]);

  useEffect(() => {
    load();
  }, [load]);

  // Poll faster while a scan is in flight so the user actually sees the
  // ingest → parse → graph → analysis → reporting transitions.
  const inflight = scan?.status === "RUNNING" || scan?.status === "QUEUED";
  useEffect(() => {
    if (!inflight) return;
    const t = setInterval(load, 1500);
    return () => clearInterval(t);
  }, [inflight, load]);

  const sevData = useMemo(
    () =>
      findings
        ? Object.entries(findings.severity_counts).map(([name, value]) => ({ name, value }))
        : [],
    [findings],
  );
  const vulnData = useMemo(
    () =>
      findings
        ? Object.entries(findings.vuln_type_counts).map(([name, value]) => ({ name, value }))
        : [],
    [findings],
  );

  const vulnColor = (name: string, idx: number) => {
    if (name === "Other") return "#94a3b8";
    return VULN_PALETTE[idx % VULN_PALETTE.length];
  };

  return (
    <div className="p-8 max-w-7xl mx-auto theme-transition">
      <Link
        to="/"
        className="inline-flex items-center gap-1 text-sm text-brand-orange font-medium mb-4 hover:underline"
      >
        <ArrowLeft className="w-4 h-4" /> Back to dashboard
      </Link>

      {error && (
        <div className="mb-4 p-4 rounded-xl bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 text-red-800 dark:text-red-300 text-sm">
          {error}
        </div>
      )}

      {scan && (
        <header className="mb-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-fg tracking-tight">
                {scan.source_label || scan.plugin_slug}
              </h1>
              <p className="text-muted text-sm mt-1 font-mono">{scan.scan_id}</p>
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              <StatusPill status={scan.status} />
              {scan.status === "FAILED" && scan.error_message && (
                <span className="text-sm text-red-600 dark:text-red-400 max-w-md">
                  {scan.error_message}
                </span>
              )}
              <span className="text-lg font-bold text-fg tabular-nums">
                {scan.findings_count} findings
              </span>
              {scanId && (
                <DownloadReportButton
                  scanId={scanId}
                  disabled={scan.status === "RUNNING" || scan.status === "QUEUED"}
                  params={{
                    ...(severity && { severity }),
                    ...(vulnType && { vuln_type: vulnType }),
                  }}
                />
              )}
              {scanId && <DeleteScanButton scanId={scanId} onDeleted={() => nav("/")} />}
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <ChartCard
          title="Severity breakdown"
          subtitle={`${sevData.reduce((a, d) => a + d.value, 0)} total · click a slice to filter`}
          icon={<ShieldAlert className="w-4 h-4 text-brand-orange" />}
          activeFilter={severity}
          onClear={() => setSeverity("")}
        >
          {sevData.length === 0 ? (
            <EmptyMini message="No severity data yet." />
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-center">
              <InteractiveDonut
                data={sevData}
                colors={(name) => SEV_COLORS[name] ?? "#64748b"}
                selected={severity}
                onSelect={setSeverity}
                centerLabel="findings"
                height={240}
              />
              <DonutLegend
                data={sevData}
                colors={(name) => SEV_COLORS[name] ?? "#64748b"}
                selected={severity}
                onSelect={setSeverity}
              />
            </div>
          )}
        </ChartCard>

        <ChartCard
          title="Vulnerability types"
          subtitle={`${vulnData.length} types · click a slice to filter`}
          icon={<Bug className="w-4 h-4 text-brand-orange" />}
          activeFilter={vulnType}
          onClear={() => setVulnType("")}
        >
          {vulnData.length === 0 ? (
            <EmptyMini message="Vulnerability-type breakdown will appear once the scan reports findings." />
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-center">
              <InteractiveDonut
                data={vulnData}
                colors={vulnColor}
                selected={vulnType}
                onSelect={setVulnType}
                centerLabel="findings"
                height={240}
              />
              <DonutLegend
                data={[...vulnData].sort((a, b) => b.value - a.value)}
                colors={vulnColor}
                selected={vulnType}
                onSelect={setVulnType}
              />
            </div>
          )}
        </ChartCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="lg:col-span-1 bg-card rounded-2xl border border-border p-6 shadow-sm h-fit">
          <h2 className="font-semibold text-fg mb-4 flex items-center gap-2">
            <Filter className="w-4 h-4 text-brand-orange" /> Filters
          </h2>
          <div className="space-y-4">
            <label className="block text-sm">
              <span className="font-medium text-fg">Severity</span>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-border bg-card text-fg outline-none focus:ring-2 focus:ring-brand-orange/30 focus:border-brand-orange"
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
              <span className="font-medium text-fg">Vulnerability type</span>
              <select
                value={vulnType}
                onChange={(e) => setVulnType(e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-lg border border-border bg-card text-fg outline-none focus:ring-2 focus:ring-brand-orange/30 focus:border-brand-orange"
              >
                <option value="">All types</option>
                {VULN_TYPES.filter(Boolean).map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>
            {(severity || vulnType) && (
              <button
                type="button"
                onClick={() => {
                  setSeverity("");
                  setVulnType("");
                }}
                className="text-xs font-medium text-brand-orange hover:underline"
              >
                Clear all filters
              </button>
            )}
          </div>
        </div>

        <div className="lg:col-span-2 bg-card rounded-2xl border border-border shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b border-border flex items-center justify-between gap-3 flex-wrap">
            <h2 className="font-semibold text-fg flex items-center gap-2">
              <FileSearch className="w-4 h-4 text-brand-orange" />
              Vulnerabilities {findings ? `(${findings.total})` : ""}
            </h2>
            <div className="flex items-center gap-2 flex-wrap">
              {severity && (
                <ActiveFilterChip label={`Severity: ${severity}`} onClear={() => setSeverity("")} />
              )}
              {vulnType && (
                <ActiveFilterChip label={`Type: ${vulnType}`} onClear={() => setVulnType("")} />
              )}
            </div>
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

function ChartCard({
  title,
  subtitle,
  icon,
  activeFilter,
  onClear,
  children,
}: {
  title: string;
  subtitle?: string;
  icon?: React.ReactNode;
  activeFilter?: string;
  onClear?: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-card rounded-2xl border border-border p-6 shadow-sm">
      <div className="flex items-baseline justify-between mb-4 gap-3">
        <h2 className="font-semibold text-fg flex items-center gap-2">
          {icon}
          {title}
        </h2>
        <div className="flex items-center gap-2">
          {activeFilter && (
            <ActiveFilterChip label={activeFilter} onClear={onClear} small />
          )}
          {subtitle && <span className="text-xs text-muted">{subtitle}</span>}
        </div>
      </div>
      {children}
    </div>
  );
}

function ActiveFilterChip({
  label,
  onClear,
  small,
}: {
  label: string;
  onClear?: () => void;
  small?: boolean;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full bg-brand-orange-soft text-brand-orange font-medium ring-1 ring-brand-orange/30 ${
        small ? "text-[11px] px-2 py-0.5" : "text-xs px-2.5 py-1"
      }`}
    >
      {label}
      {onClear && (
        <button
          type="button"
          onClick={onClear}
          className="ml-0.5 leading-none hover:text-brand-orange-hover"
          aria-label="Clear filter"
        >
          ×
        </button>
      )}
    </span>
  );
}

function EmptyMini({ message }: { message: string }) {
  return (
    <div className="h-[240px] flex items-center justify-center">
      <p className="text-muted text-sm text-center max-w-[260px]">{message}</p>
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
          <span className="text-sm font-semibold text-fg">{label}</span>
        </div>
        <span className="text-sm font-mono text-fg tabular-nums">{value.toFixed(0)}%</span>
      </div>
      <div className="h-2 w-full rounded-full bg-surface border border-border overflow-hidden">
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
    <li className="px-6 py-4 hover:bg-brand-orange-soft/40 dark:hover:bg-white/[0.02] transition-colors">
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <SeverityBadge severity={f.severity} />
        <span className="text-xs font-mono text-muted">{f.rule_id}</span>
        <span className="text-xs px-2 py-0.5 rounded bg-surface text-fg-muted border border-border">
          {f.vuln_type}
        </span>
      </div>
      <p className="font-medium text-fg">{f.title}</p>
      {f.file_path && (
        <p className="text-sm text-muted mt-1 font-mono">
          {f.file_path}
          {f.start_line != null ? `:${f.start_line}` : ""}
        </p>
      )}
      {f.confidence_score != null && (
        <p className="text-xs text-muted mt-1">
          Confidence: {(f.confidence_score * 100).toFixed(0)}%
        </p>
      )}
    </li>
  );
}
