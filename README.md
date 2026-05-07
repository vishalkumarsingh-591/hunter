# Hunter (PART 1 MVP)

Deterministic-first static analysis for **local WordPress plugin** directories: ingestion → tree-sitter parse → in-memory knowledge graph → WordPress semantics → coarse taint → YAML rules → static verification → confidence → reports.

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
python -m hunter.cli.main tests\fixtures\wp_plugins\minimal_plugin
```

### 5) Run a scan (your local plugin path)
```powershell
python -m hunter.cli.main "C:\path\to\wp-content\plugins\some-plugin"
```

### Output
Outputs default to `./output/<plugin-slug>/` and include:
- `reports/summary.md` (human summary)
- `reports/findings.json` (machine-readable report)
- `findings/enriched.jsonl` (one JSON per enriched finding)
- `evidence/<id>/source_excerpt.txt` (bounded excerpts)

### CLI note (common gotcha)
The current MVP CLI expects **only the plugin path** (no `scan` subcommand):
- ✅ `python -m hunter.cli.main <plugin_path>`
- ❌ `python -m hunter.cli.main scan <plugin_path>`

## Configuration

- `config/default.yaml` — quotas, graph schema version, optional `persistence.database_url` (Postgres or `sqlite:///...`), optional Neo4j URI.
- Env vars use prefix `HUNTER_` (see `hunter.settings.HunterSettings`).

## API (optional)

```powershell
uvicorn hunter.api.main:app --reload
```

`POST /scans` with `{"plugin_path": "C:\\path\\to\\plugin"}` runs the same `ScanRunner` as the CLI.

## SRS

See [docs/srs/part1-static-mvp.md](docs/srs/part1-static-mvp.md).
