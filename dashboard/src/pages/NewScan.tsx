import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Github, Upload, Loader2, Search, Link2, FolderOpen } from "lucide-react";
import { api, GitHubRepo } from "../api/client";

const TOKEN_KEY = "hunter_github_token";

export default function NewScan() {
  const nav = useNavigate();
  const [tab, setTab] = useState<"github" | "upload">("github");
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) ?? "");
  const [repoUrl, setRepoUrl] = useState("");
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [filter, setFilter] = useState("");
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [cloning, setCloning] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [drag, setDrag] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const saveToken = (t: string) => {
    setToken(t);
    localStorage.setItem(TOKEN_KEY, t);
  };

  const tokenLooksWrong =
    token.trim().length > 0 &&
    (/[\s:/@]/.test(token.trim()) || token.trim().includes("github.com"));

  const clearToken = () => {
    setToken("");
    localStorage.removeItem(TOKEN_KEY);
  };

  const loadRepos = async () => {
    setError(null);
    setLoadingRepos(true);
    try {
      const list = await api.listRepos(token);
      setRepos(list);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load repos");
    } finally {
      setLoadingRepos(false);
    }
  };

  const cloneRepo = async (fullName: string) => {
    const [owner, repo] = fullName.split("/");
    setCloning(fullName);
    setError(null);
    try {
      const res = await api.cloneRepo({ owner, repo }, token);
      setMessage(res.message);
      nav(`/scan/${res.scan_id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Clone failed");
    } finally {
      setCloning(null);
    }
  };

  const cloneFromUrl = async () => {
    if (tokenLooksWrong) {
      setError(
        "The GitHub token field looks like a URL or path. Clear it (or paste a real PAT like ghp_…) before cloning.",
      );
      return;
    }
    setCloning("url");
    setError(null);
    try {
      const res = await api.cloneRepoUrl({ url: repoUrl.trim() }, token || undefined);
      setMessage(res.message);
      nav(`/scan/${res.scan_id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Clone failed");
    } finally {
      setCloning(null);
    }
  };

  const onUpload = useCallback(
    async (file: File) => {
      setUploading(true);
      setError(null);
      try {
        const res = await api.upload(file);
        setMessage(res.message);
        nav(`/scan/${res.scan_id}`);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Upload failed");
      } finally {
        setUploading(false);
      }
    },
    [nav],
  );

  const onFolder = useCallback(
    async (files: FileList | null) => {
      if (!files?.length) return;
      setUploading(true);
      setError(null);
      try {
        const res = await api.uploadFolder(files);
        setMessage(res.message);
        nav(`/scan/${res.scan_id}`);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Folder upload failed");
      } finally {
        setUploading(false);
      }
    },
    [nav],
  );

  const filtered = repos.filter(
    (r) =>
      r.full_name.toLowerCase().includes(filter.toLowerCase()) ||
      (r.description ?? "").toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <div className="p-8 max-w-4xl mx-auto theme-transition">
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-fg tracking-tight">New analysis</h1>
        <p className="text-muted mt-1.5">GitHub URL, repository list, ZIP archive, or plugin folder</p>
      </header>

      <div className="flex gap-2 mb-6 p-1 bg-card rounded-xl border border-border inline-flex">
        <TabButton active={tab === "github"} onClick={() => setTab("github")} icon={Github} label="GitHub" />
        <TabButton active={tab === "upload"} onClick={() => setTab("upload")} icon={Upload} label="Upload" />
      </div>

      {error && (
        <div className="mb-4 p-4 rounded-xl bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 text-red-800 dark:text-red-300 text-sm">
          {error}
        </div>
      )}
      {message && (
        <div className="mb-4 p-4 rounded-xl bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 text-emerald-800 dark:text-emerald-300 text-sm">
          {message}
        </div>
      )}

      {tab === "github" && (
        <div className="bg-card rounded-2xl border border-border p-6 shadow-sm space-y-5">
          <div>
            <label className="block text-sm font-medium text-fg mb-1">
              <Link2 className="inline w-4 h-4 mr-1 -mt-0.5" />
              Clone from URL
            </label>
            <div className="flex gap-2">
              <input
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repository"
                className="flex-1 px-4 py-3 rounded-xl border border-border bg-card text-fg placeholder:text-muted focus:ring-2 focus:ring-brand-orange/40 focus:border-brand-orange outline-none transition"
              />
              <button
                type="button"
                disabled={!repoUrl.trim() || cloning !== null}
                onClick={cloneFromUrl}
                className="shrink-0 px-5 py-3 rounded-xl bg-brand-navy text-white font-medium hover:bg-brand-navy-light disabled:opacity-50 transition-all hover:-translate-y-0.5"
              >
                {cloning === "url" ? <Loader2 className="w-4 h-4 animate-spin" /> : "Analyze"}
              </button>
            </div>
            <p className="text-xs text-muted mt-1.5">
              Public repos work without a token. Private repos need a PAT below.
            </p>
          </div>

          <hr className="border-border" />

          <label className="block">
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-medium text-fg">
                GitHub token (optional for public URL)
              </span>
              {token && (
                <button
                  type="button"
                  onClick={clearToken}
                  className="text-xs text-brand-orange hover:underline"
                >
                  Clear
                </button>
              )}
            </div>
            <input
              type="password"
              value={token}
              onChange={(e) => saveToken(e.target.value)}
              placeholder="ghp_… or github_pat_…"
              className={`w-full px-4 py-3 rounded-xl border bg-card text-fg placeholder:text-muted outline-none transition focus:ring-2 ${
                tokenLooksWrong
                  ? "border-red-400 focus:ring-red-200 focus:border-red-500"
                  : "border-border focus:ring-brand-orange/40 focus:border-brand-orange"
              }`}
            />
            {tokenLooksWrong && (
              <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                This looks like a URL or path. Paste only your Personal Access Token here — the repo URL goes in the field above.
              </p>
            )}
          </label>
          <button
            type="button"
            onClick={loadRepos}
            disabled={!token || loadingRepos}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-orange text-white font-medium hover:bg-brand-orange-hover disabled:opacity-50 transition shadow-md shadow-brand-orange/20"
          >
            {loadingRepos ? <Loader2 className="w-4 h-4 animate-spin" /> : <Github className="w-4 h-4" />}
            Load my repositories
          </button>

          {repos.length > 0 && (
            <>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
                <input
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="Filter repositories…"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-border bg-card text-fg placeholder:text-muted outline-none focus:ring-2 focus:ring-brand-orange/30 focus:border-brand-orange transition"
                />
              </div>
              <ul className="divide-y divide-border max-h-80 overflow-auto rounded-xl border border-border">
                {filtered.map((r) => (
                  <li
                    key={r.full_name}
                    className="flex items-center justify-between px-4 py-3 hover:bg-brand-orange-soft/40 dark:hover:bg-white/[0.02] transition-colors"
                  >
                    <div>
                      <p className="font-medium text-fg">{r.full_name}</p>
                      {r.description && <p className="text-xs text-muted line-clamp-1">{r.description}</p>}
                    </div>
                    <button
                      type="button"
                      disabled={cloning !== null}
                      onClick={() => cloneRepo(r.full_name)}
                      className="text-sm px-4 py-2 rounded-lg bg-brand-navy text-white hover:bg-brand-navy-light disabled:opacity-50 transition-all hover:-translate-y-0.5"
                    >
                      {cloning === r.full_name ? <Loader2 className="w-4 h-4 animate-spin" /> : "Analyze"}
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      {tab === "upload" && (
        <div className="space-y-4">
          <div
            className={`bg-card rounded-2xl border-2 border-dashed p-12 text-center transition-all ${
              drag
                ? "border-brand-orange bg-brand-orange-soft scale-[1.01]"
                : "border-border hover:border-brand-orange/60"
            }`}
            onDragOver={(e) => {
              e.preventDefault();
              setDrag(true);
            }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDrag(false);
              const f = e.dataTransfer.files[0];
              if (f) onUpload(f);
            }}
          >
            <Upload className="w-12 h-12 mx-auto text-brand-orange mb-4" />
            <p className="font-medium text-fg">Drop a ZIP of your WordPress plugin</p>
            <p className="text-sm text-muted mt-1 mb-4">Or choose a file (max 512 MB)</p>
            <label className="inline-flex cursor-pointer items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-orange text-white font-medium hover:bg-brand-orange-hover shadow-md shadow-brand-orange/25 transition-all hover:-translate-y-0.5">
              {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              Select ZIP
              <input
                type="file"
                accept=".zip,.tar.gz,.tgz"
                className="hidden"
                disabled={uploading}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) onUpload(f);
                }}
              />
            </label>
          </div>

          <div className="bg-card rounded-2xl border border-border p-8 text-center shadow-sm">
            <FolderOpen className="w-10 h-10 mx-auto text-brand-navy dark:text-sky-300 mb-3" />
            <p className="font-medium text-fg">Upload plugin folder directly</p>
            <p className="text-sm text-muted mt-1 mb-4">Select the root folder of your WordPress plugin</p>
            <label className="inline-flex cursor-pointer items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-navy text-white font-medium hover:bg-brand-navy-light shadow-md transition-all hover:-translate-y-0.5">
              {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <FolderOpen className="w-4 h-4" />}
              Choose folder
              <input
                type="file"
                className="hidden"
                disabled={uploading}
                // @ts-expect-error webkitdirectory is non-standard but widely supported
                webkitdirectory=""
                directory=""
                multiple
                onChange={(e) => onFolder(e.target.files)}
              />
            </label>
          </div>
        </div>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition ${
        active
          ? "bg-brand-orange text-white shadow"
          : "text-fg-muted hover:bg-surface hover:text-fg"
      }`}
    >
      <Icon className="w-4 h-4" />
      {label}
    </button>
  );
}
