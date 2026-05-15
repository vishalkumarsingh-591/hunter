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

## API (optional)

Minimal FastAPI service (same `ScanRunner` as the CLI for synchronous scans):

```powershell
uvicorn hunter.api.main:app --reload
```

`POST /scans` with `{"plugin_path": "C:\\path\\to\\plugin"}` expects an **existing directory on the machine running the API**.

## Documentation

- **Phase 1 baseline / product framing:** [docs/srs/part1-static-mvp.md](docs/srs/part1-static-mvp.md)  
- **Dev tooling & graph-first rules:** [docs/dev-tooling.md](docs/dev-tooling.md)  
- **Fact-graph contract:** [docs/graph-models/fact-graph-contract.md](docs/graph-models/fact-graph-contract.md)  
- **Graph model changelog:** [docs/graph-models/CHANGELOG.md](docs/graph-models/CHANGELOG.md)
