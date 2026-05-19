const API_BASE = import.meta.env.VITE_API_URL ?? "";

function headers(githubToken?: string): HeadersInit {
  const h: Record<string, string> = { Accept: "application/json" };
  if (githubToken?.trim()) h["X-GitHub-Token"] = githubToken.trim();
  return h;
}

async function parseError(res: Response): Promise<string> {
  const text = await res.text();
  try {
    const j = JSON.parse(text) as { detail?: string };
    if (j.detail) return j.detail;
  } catch {
    /* plain text */
  }
  return text || res.statusText;
}

async function request<T>(path: string, init?: RequestInit & { githubToken?: string }): Promise<T> {
  const { githubToken, ...rest } = init ?? {};
  const res = await fetch(`${API_BASE}${path}`, {
    ...rest,
    headers: { ...headers(githubToken), ...(rest.headers as Record<string, string>) },
  });
  if (!res.ok) {
    throw new Error(await parseError(res));
  }
  return res.json() as Promise<T>;
}

export type ScanSummary = {
  scan_id: string;
  plugin_slug: string;
  status: string;
  source_type: string;
  source_label: string | null;
  findings_count: number;
  started_at: string | null;
  finished_at: string | null;
  snapshot_id: string | null;
  error_message: string | null;
  progress: string | null;
  progress_pct: number | null;
  stage: string | null;
};

export type ScanDetail = ScanSummary & {
  output_dir: string | null;
  replay_token: string | null;
};

export type FindingSummary = {
  finding_id: string;
  rule_id: string;
  severity: string;
  vuln_type: string;
  title: string;
  file_path: string | null;
  start_line: number | null;
  confidence_score: number | null;
  verification_status: string | null;
};

export type FindingsPage = {
  scan_id: string;
  total: number;
  items: FindingSummary[];
  severity_counts: Record<string, number>;
  rule_counts: Record<string, number>;
};

export type GitHubRepo = {
  full_name: string;
  name: string;
  private: boolean;
  default_branch: string;
  html_url: string;
  description: string | null;
};

export type ScanStats = {
  total_scans: number;
  by_severity: Record<string, number>;
  by_vuln_type: Record<string, number>;
};

export const api = {
  health: () => request<{ status: string }>("/api/health"),
  listScans: (limit = 50) => request<ScanSummary[]>(`/api/scans?limit=${limit}`),
  getScan: (id: string) => request<ScanDetail>(`/api/scans/${id}`),
  deleteScan: (id: string, deleteArtifacts = true) =>
    request<{ scan_id: string; deleted: boolean; message: string }>(
      `/api/scans/${id}?delete_artifacts=${deleteArtifacts}`,
      { method: "DELETE" },
    ),
  getFindings: (id: string, params: Record<string, string>) => {
    const q = new URLSearchParams(params).toString();
    return request<FindingsPage>(`/api/scans/${id}/findings?${q}`);
  },
  stats: () => request<ScanStats>("/api/scans/stats/overview"),
  listRepos: (token: string) =>
    request<GitHubRepo[]>("/api/github/repos", { githubToken: token }),
  cloneRepo: (body: { owner: string; repo: string; ref?: string }, token: string) =>
    request<{ scan_id: string; status: string; message: string }>("/api/github/clone", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      githubToken: token,
    }),
  cloneRepoUrl: (body: { url: string; ref?: string }, token?: string) =>
    request<{ scan_id: string; status: string; message: string }>("/api/github/clone-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      githubToken: token,
    }),
  upload: async (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`${API_BASE}/api/uploads`, { method: "POST", body: fd });
    if (!res.ok) throw new Error(await parseError(res));
    return res.json() as Promise<{ scan_id: string; status: string; message: string }>;
  },
  uploadFolder: async (files: FileList) => {
    const fd = new FormData();
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const rel = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
      fd.append("files", f, rel);
    }
    const res = await fetch(`${API_BASE}/api/uploads/folder`, { method: "POST", body: fd });
    if (!res.ok) throw new Error(await parseError(res));
    return res.json() as Promise<{ scan_id: string; status: string; message: string }>;
  },
};
