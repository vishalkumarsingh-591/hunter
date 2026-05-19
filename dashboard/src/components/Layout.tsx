import { Link, Outlet, useLocation } from "react-router-dom";
import { LayoutDashboard, PlusCircle, Shield } from "lucide-react";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scan/new", label: "New Scan", icon: PlusCircle },
];

export default function Layout() {
  const loc = useLocation();
  return (
    <div className="min-h-screen flex">
      <aside className="w-64 shrink-0 bg-brand-navy/95 border-r border-white/10 flex flex-col">
        <div className="px-6 py-8 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-brand-orange flex items-center justify-center shadow-lg shadow-brand-orange/30">
              <Shield className="w-5 h-5 text-white" strokeWidth={2.2} />
            </div>
            <div>
              <p className="text-white font-semibold text-lg leading-tight">Hunter</p>
              <p className="text-white/50 text-xs">Static Security Analysis</p>
            </div>
          </div>
        </div>
        <nav className="flex-1 px-3 py-6 space-y-1">
          {nav.map(({ to, label, icon: Icon }) => {
            const active = loc.pathname === to || (to !== "/" && loc.pathname.startsWith(to));
            return (
              <Link
                key={to}
                to={to}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${
                  active
                    ? "bg-brand-orange text-white shadow-md shadow-brand-orange/25"
                    : "text-white/70 hover:bg-white/10 hover:text-white"
                }`}
              >
                <Icon className="w-4 h-4" />
                {label}
              </Link>
            );
          })}
        </nav>
        <p className="px-6 py-4 text-[11px] text-white/40 border-t border-white/10">
          Powered by Hunter deterministic analysis
        </p>
      </aside>
      <main className="flex-1 min-h-screen bg-surface rounded-tl-3xl shadow-2xl overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
