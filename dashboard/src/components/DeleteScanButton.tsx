import { useState } from "react";
import { Trash2, Loader2 } from "lucide-react";
import { api } from "../api/client";

type Props = {
  scanId: string;
  label?: string;
  onDeleted?: () => void;
  className?: string;
  variant?: "icon" | "button";
};

export default function DeleteScanButton({
  scanId,
  label = "Delete",
  onDeleted,
  className = "",
  variant = "button",
}: Props) {
  const [busy, setBusy] = useState(false);

  const handleClick = async () => {
    const ok = window.confirm(
      "Delete this scan and its reports? This cannot be undone.",
    );
    if (!ok) return;
    setBusy(true);
    try {
      await api.deleteScan(scanId);
      onDeleted?.();
    } catch (e) {
      window.alert(e instanceof Error ? e.message : "Delete failed");
    } finally {
      setBusy(false);
    }
  };

  if (variant === "icon") {
    return (
      <button
        type="button"
        title="Delete scan"
        disabled={busy}
        onClick={handleClick}
        className={`p-2 rounded-lg text-slate-500 hover:text-red-600 hover:bg-red-50 transition disabled:opacity-50 ${className}`}
      >
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
      </button>
    );
  }

  return (
    <button
      type="button"
      disabled={busy}
      onClick={handleClick}
      className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-red-200 text-red-700 bg-red-50 hover:bg-red-100 text-sm font-medium transition disabled:opacity-50 ${className}`}
    >
      {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
      {label}
    </button>
  );
}
