# Hunter (Phase 2)

Deterministic-first static analysis for **local WordPress plugin** directories. Phase 2 adds a **structure-complete graph**, **semantic lift (IR v2)**, **interprocedural resolution**, optional **CFG + SSA**, **path-sensitive taint**, **WordPress semantics v2**, **security facts / signals on the graph**, and **graph-query rule evaluators**—all feeding YAML-defined rules, confidence scoring, static verification hooks, and grouped reports.

Pipeline in order: **ingestion → tree-sitter parse + lift v2 → in-memory graph (schema v3) → security / WP augmentation → analysis graph (resolver / taint / layers) → rule pack → enrichment → reports.**

## Quickstart

### 1) Create + activate venv

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
```

### 2) Install the project (editable)

```powershell
pip install -e .
```

### 3) Run tests

```powershell
pytest -q
```

### 4) Run a scan (example fixture)

```powershell
hunter scan tests\fixtures\wp_plugins\minimal_plugin
```

Or without installing the console script:

```powershell
python -m hunter.cli.main scan tests\fixtures\wp_plugins\minimal_plugin
```

### 5) Run a scan (your local plugin path)

```powershell
hunter scan "C:\path\to\wp-content\plugins\some-plugin"
```

Use `hunter scan --help` for `--config`, `--output-root`, `--agents`, and `--no-progress`.

## Output

Artifacts default to `./output/<plugin-slug>/`, including:

- `reports/summary.md` — human-readable summary  
- `reports/summary_groups.json` — grouped findings for triage  
- `reports/summary_triage.md` — triage-oriented summary  
- `reports/findings.json` / `reports/findings_compact.json` — machine-readable reports  
- `findings/enriched.jsonl`, `findings/candidates.jsonl` — per-finding streams  
- `evidence/<id>/` — bounded excerpts and witness metadata  
- `semantic_graph/` — exported graph / IR diagnostics (as configured)

## Configuration

- **`config/default.yaml`** — ingest/parse quotas, **`graph.schema_version`** (v3), **`semantic.*`** (IR v2, resolver, CFG/SSA, path-sensitive taint, WP semantics v2, security popchain, limits), analysis/taint/agent settings, optional **`persistence.database_url`** (Postgres or SQLite), optional Neo4j for schema metadata / bulk export flags.
- **Environment** — prefix `HUNTER_` (see `hunter.settings.HunterSettings`).

Tuning heavy scans: many semantic flags can be turned off or limits lowered under `semantic` for faster triage runs.

## Web dashboard

React UI + FastAPI backend (GitHub connect, ZIP upload, async scans, PostgreSQL/SQLite findings).

### 1) API

```powershell
pip install -e .
uvicorn hunter.api.main:app --host 127.0.0.1 --port 8000
```

Scans run in a **background worker process** with a fast dashboard profile. Stuck scans after an API restart are marked failed on startup — delete them and run again.

Optional: `HUNTER_DATABASE_URL=postgresql://user:pass@localhost/hunter` (defaults to SQLite at `workspaces/data/hunter.db`).  
GitHub: set `HUNTER_GITHUB_TOKEN` or pass `X-GitHub-Token` from the UI.

### 2) Frontend (dev)

```powershell
cd dashboard
npm install
npm run dev
```

Open http://localhost:5173 — Vite proxies `/api` to the API.

### 3) Production-style (single server)

```powershell
cd dashboard && npm run build
uvicorn hunter.api.main:app --host 0.0.0.0 --port 8000
```

Serves the built UI from `dashboard/dist` when present.

## API (legacy sync)

`POST /scans` with `{"plugin_path": "C:\\path\\to\\plugin"}` runs a **blocking** scan (same engine as CLI). Prefer `/api/uploads` or `/api/github/clone` for the dashboard workflow.

## Documentation

- **Phase 1 baseline / product framing:** [docs/srs/part1-static-mvp.md](docs/srs/part1-static-mvp.md)  
- **Dev tooling & graph-first rules:** [docs/dev-tooling.md](docs/dev-tooling.md)  
- **Fact-graph contract:** [docs/graph-models/fact-graph-contract.md](docs/graph-models/fact-graph-contract.md)  
- **Graph model changelog:** [docs/graph-models/CHANGELOG.md](docs/graph-models/CHANGELOG.md)
