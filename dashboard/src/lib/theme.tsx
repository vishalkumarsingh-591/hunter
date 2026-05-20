import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type Theme = "light" | "dark";
const STORAGE_KEY = "hunter_theme";

type ThemeCtx = {
  theme: Theme;
  setTheme: (t: Theme) => void;
  toggle: () => void;
};

const Ctx = createContext<ThemeCtx | null>(null);

function resolveInitial(): Theme {
  if (typeof window === "undefined") return "light";
  const saved = window.localStorage.getItem(STORAGE_KEY);
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => resolveInitial());

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute("data-theme", theme);
    root.classList.add("theme-transition");
    const tid = window.setTimeout(() => root.classList.remove("theme-transition"), 350);
    window.localStorage.setItem(STORAGE_KEY, theme);
    return () => window.clearTimeout(tid);
  }, [theme]);

  // Follow system changes only if user has not explicitly chosen one.
  useEffect(() => {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark") return;
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!mq) return;
    const onChange = (e: MediaQueryListEvent) => setThemeState(e.matches ? "dark" : "light");
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);

  const setTheme = useCallback((t: Theme) => setThemeState(t), []);
  const toggle = useCallback(() => setThemeState((t) => (t === "dark" ? "light" : "dark")), []);

  const value = useMemo(() => ({ theme, setTheme, toggle }), [theme, setTheme, toggle]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTheme must be used within ThemeProvider");
  return v;
}
