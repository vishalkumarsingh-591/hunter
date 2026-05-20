# Graph model changelog

## Zero-config full-quality performance

- Auto **workers** / **max_inflight** from CPU + RAM (`detect_system_resources`); cap 16 workers on large hosts.
- **Stable edge IDs** (content hash) in [`InMemoryGraph`](src/hunter/graph/in_memory.py); sorted `rels.jsonl` export.
- **Parallel per-file graph augmentation** ([`graph/shard.py`](src/hunter/graph/shard.py)): structural import, security facts, WP semantics; deterministic merge.
- **Resolver O(E)** via callsite→callee index ([`resolver_graph.py`](src/hunter/analysis/semantic/resolver_graph.py)).
- **Parallel rule evaluation** (read-only graph; sorted merge).
- Reports: `scan_resources` metadata in `findings.json`.

## Tier A parallel scan (behavior-preserving)

- `scan.workers` / `scan.max_inflight` in config; CLI `--workers`; env `HUNTER_SCAN_WORKERS`, `HUNTER_SCAN_MAX_INFLIGHT`.
- Parallel: per-file parse (`ProcessPoolExecutor`), ingest SHA256, snapshot copy, IR JSON export.
- Unchanged serial path: graph build, security augment, CFG/SSA/taint, rules, `replay_token` contract (`workers=1` vs `workers>1` equivalence tested).

## Schema 3.1 (profile-driven catalogs — Part 2.1)

- Security **sources/sinks/sanitizers** loaded from YAML catalogs under `analysis/rules/catalogs/` (`generic-php-v1`, `wordpress-v1`).
- **Scan profiles**: `auto`, `generic-php`, `wordpress`, `full` compose catalogs, adapters, and rule packs.
- **Platform adapters** registry (`wordpress` → hooks/REST/AJAX + entrypoint stub nodes).
- `DeterminismMeta` extended with `scan_profile` and `catalog_hash`.
- `CandidateFinding.exposure_context` for future reachability gating.
- Reports: `summary_by_owasp.json` from rule `owasp_ids` metadata.

## Schema 3 (structure-complete graph)

- IR lift v2 for PHP, JavaScript, HTML with structural `IREdge` kinds.
- Graph nodes: `Class`, `Function`, `Method`, `Callsite`, `Symbol`.
- `File` nodes include `parse_status`, `ir_node_count`, `lift_truncated`.
- Default rule pack v3 with expanded vulnerability families.

## Schema 2 (fact-security augment)

- Parse-driven `Source` / `Sink` / `Sanitizer` / `HeuristicPattern` nodes (see `hunter.graph.fact_security_augment`).
- Rule packs may declare `min_graph_schema_version: "2"` for evaluators that require these nodes.

## Schema 1 (baseline)

- File + IRNode from parse; WordPress and regex taint augmentors.
