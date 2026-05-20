const map: Record<string, string> = {
  COMPLETED:
    "bg-emerald-100 text-emerald-800 ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-300 dark:ring-emerald-500/30",
  RUNNING:
    "bg-blue-100 text-blue-800 ring-blue-200 animate-pulse dark:bg-blue-500/15 dark:text-blue-300 dark:ring-blue-500/30",
  QUEUED:
    "bg-amber-100 text-amber-800 ring-amber-200 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-500/30",
  FAILED:
    "bg-red-100 text-red-800 ring-red-200 dark:bg-red-500/15 dark:text-red-300 dark:ring-red-500/30",
};

export default function StatusPill({ status }: { status: string }) {
  const cls = map[status] ?? "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-500/15 dark:text-slate-300 dark:ring-slate-500/30";
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ring-1 ring-inset ${cls}`}>
      {status}
    </span>
  );
}
