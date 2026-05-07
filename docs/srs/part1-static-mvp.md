# SRS — PART 1 Trustworthy Static Analysis MVP

| Field | Value |
|-------|--------|
| **srs_version** | 1.0.0 |
| **freeze_date** | 2026-05-07 |
| **status** | Frozen for PART 1 implementation |

## 1. Purpose

Deliver an industry-grade, **deterministic-first** static vulnerability analysis MVP for **local WordPress plugin** directories, with graph-centric evidence, static-only verification, reproducible outputs, and LangGraph-orchestrated reasoning that **never discovers vulnerabilities without deterministic anchors**.

## 2. Scope

### In scope

- CLI: `hunter scan /path/to/plugin`
- Repository ingestion with quotas and manifest
- tree-sitter parsing (PHP, JavaScript, HTML) → IR + comments + line maps
- Knowledge graph materialization (Neo4j when configured; file-backed graph export always)
- WordPress semantic extraction (hooks, AJAX, REST, capabilities, nonces)
- Hybrid taint analysis (NetworkX intraprocedural → graph edges)
- YAML rule packs and deterministic rule runner
- Static verification (non-LLM)
- Confidence scoring from features only (YAML weights)
- Reporting under configurable output root
- PostgreSQL scan/findings/audit persistence when `DATABASE_URL` set
- FastAPI minimal scan API
- structlog logging, metrics counters, optional OpenTelemetry hook

### Out of scope (PART 1)

- Execution of plugin code, `eval`, fuzzing, browser automation
- Dynamic exploit verification or sandboxed runtime
- LLM-based vulnerability discovery or severity finalization without gates
- Raw LLM confidence as score input

## 3. Normative references

- Plan: PART 1 architecture plan (implementation source)
- Project rules: `.cursor/rules/*.mdc`
- Graph docs: `.cursor/graphs/*.md`

## 4. CLI contract

- **Command**: `hunter scan PATH [--output-root DIR] [--snapshot-mode copy|manifest-only] [--agents-enabled/--no-agents]`
- **Output layout**: `{output_root}/{plugin_slug}/` containing:
  - `repository_snapshot/`
  - `semantic_graph/`
  - `findings/`
  - `evidence/`
  - `reasoning/`
  - `reports/`
  - `logs/`
  - `cache/`

**Portability**: Default `output_root` = `./output`. Env `HUNTER_OUTPUT_ROOT` overrides. Literal `/output/` is not assumed on Windows.

## 5. Determinism and replay

**replay_token** components (hashed together in `DeterminismMeta`):

1. Normalized absolute plugin root path hash  
2. Content tree manifest hash (`files.jsonl` ordered paths + sha256)  
3. Parser lock hash + grammar revisions + lift version  
4. Graph schema version  
5. Rule pack hash  
6. Hunter package version  
7. `agents_disabled` flag  
8. LLM model id if agents used LLM (else empty)

**Finding IDs**: `FINDING|{rule_id}|{anchor_id}|{sink_id}|{witness_hash}` with canonical JSON for witness hash input.

## 6. Data retention and security

- Scanner must not execute plugin source.
- Logs and reports must redact lines matching configurable secret patterns.
- Neo4j/Postgres credentials via environment only.

## 7. Verification (PART 1)

**Static verification only**: secondary graph checks, witness minimization, sanitizer/context cross-checks, integrity checks. No network proof-of-exploit.

## 8. Change control

Any change to outputs, schemas, or replay_token inputs requires bumping `srs_version` and an entry in this document’s revision table.

| srs_version | date | summary |
|-------------|------|---------|
| 1.0.0 | 2026-05-07 | Initial freeze |
