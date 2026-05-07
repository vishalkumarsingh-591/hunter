# Hunter (PART 1 MVP)

Deterministic-first static analysis for **local WordPress plugin** directories: ingestion → tree-sitter parse → in-memory knowledge graph → WordPress semantics → coarse taint → YAML rules → static verification → confidence → reports.

## Quickstart

```powershell
cd c:\hunter
python -m venv .venv
.\.venv\Scripts\pip install -e ".[dev]"
.\.venv\Scripts\hunter scan tests\fixtures\wp_plugins\minimal_plugin
```

Outputs default to `./output/<plugin-slug>/` (override with `--output-root` or `HUNTER_OUTPUT_ROOT` / `config/default.yaml`).

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
