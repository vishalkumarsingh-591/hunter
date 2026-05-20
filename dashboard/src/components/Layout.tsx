import { Link, Outlet, useLocation } from "react-router-dom";
import { LayoutDashboard, Moon, PlusCircle, Shield, Sun } from "lucide-react";
import { useTheme } from "../lib/theme";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scan/new", label: "New Scan", icon: PlusCircle },
];

export default function Layout() {
  const loc = useLocation();
  const { theme, toggle } = useTheme();
  return (
    <div className="min-h-screen flex">
      <aside className="w-64 shrink-0 bg-brand-navy/95 backdrop-blur border-r border-white/10 flex flex-col">
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
        <div className="px-3 pb-3">
          <button
            type="button"
            onClick={toggle}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            className="w-full flex items-center justify-between gap-3 px-4 py-3 rounded-xl text-sm font-medium text-white/70 hover:bg-white/10 hover:text-white transition-all"
          >
            <span className="flex items-center gap-3">
              {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              {theme === "dark" ? "Light mode" : "Dark mode"}
            </span>
            <span
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                theme === "dark" ? "bg-brand-orange" : "bg-white/20"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${
                  theme === "dark" ? "translate-x-4" : "translate-x-1"
                }`}
              />
            </span>
          </button>
        </div>
        <p className="px-6 py-4 text-[11px] text-white/40 border-t border-white/10">
          Powered by Hunter deterministic analysis
        </p>
      </aside>
      <main className="flex-1 min-h-screen bg-surface text-fg rounded-tl-3xl shadow-2xl overflow-auto theme-transition">
        <Outlet />
      </main>
    </div>
  );
}
