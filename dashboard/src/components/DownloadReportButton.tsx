import { useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { api } from "../api/client";

type Props = {
  scanId: string;
  /** Optional filters (severity, vuln_type) to scope the PDF. */
  params?: Record<string, string>;
  disabled?: boolean;
  className?: string;
  label?: string;
};

export default function DownloadReportButton({
  scanId,
  params,
  disabled,
  className = "",
  label = "Download PDF",
}: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleClick = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.downloadReportPdf(scanId, params);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Download failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={`inline-flex flex-col items-end ${className}`}>
      <button
        type="button"
        onClick={handleClick}
        disabled={disabled || busy}
        title={disabled ? "Wait for the scan to finish to download the report" : label}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border bg-card text-fg hover:border-brand-orange hover:text-brand-orange disabled:opacity-50 disabled:cursor-not-allowed transition-all text-sm font-medium shadow-sm"
      >
        {busy ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <Download className="w-4 h-4" />
        )}
        {label}
      </button>
      {error && (
        <span className="mt-1 text-[11px] text-red-600 dark:text-red-400 max-w-[220px] text-right">
          {error}
        </span>
      )}
    </div>
  );
}
