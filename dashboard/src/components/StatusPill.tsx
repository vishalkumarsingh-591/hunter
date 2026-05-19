const map: Record<string, string> = {
  COMPLETED: "bg-emerald-100 text-emerald-800",
  RUNNING: "bg-blue-100 text-blue-800 animate-pulse",
  QUEUED: "bg-amber-100 text-amber-800",
  FAILED: "bg-red-100 text-red-800",
};

export default function StatusPill({ status }: { status: string }) {
  return (
    <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${map[status] ?? "bg-slate-100 text-slate-700"}`}>
      {status}
    </span>
  );
}
