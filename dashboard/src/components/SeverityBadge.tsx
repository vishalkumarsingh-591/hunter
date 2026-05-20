const styles: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white shadow-sm shadow-red-600/30",
  HIGH: "bg-orange-600 text-white shadow-sm shadow-orange-600/30",
  MEDIUM: "bg-amber-500 text-white shadow-sm shadow-amber-500/30",
  LOW: "bg-sky-600 text-white shadow-sm shadow-sky-600/30",
  INFO: "bg-slate-400 text-white",
};

export default function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toUpperCase();
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold tracking-wide ${
        styles[key] ?? "bg-slate-500 text-white"
      }`}
    >
      {key}
    </span>
  );
}
