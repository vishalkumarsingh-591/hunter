# Fact graph contract (Hunter)

## Purpose

The **fact graph** is the canonical, codebase-derived model static rules query. New vulnerability checks should prefer **new traversals** over the existing vocabulary; **additive** node/relationship kinds require a **schema version bump** and migration notes.

## Schema versioning

- `InMemoryGraph.schema_version` (from settings `graph.schema_version`) is an opaque string compared **lexicographically** for minimum requirements on rules (see `RuleSpec.min_graph_schema_version`).
- **Bump** when adding required properties, renaming labels, or changing witness semantics. Document in `docs/graph-models/CHANGELOG.md` (append entry) and `src/hunter/graph/migrations/` when Neo4j/Cypher templates exist.

## Node labels (vocabulary)

| Label | Layer | Meaning |
|--------|--------|---------|
| Repository, Snapshot, File | L0 | Repo layout |
| IRNode | L1 | Tree-sitter lift span |
| Class, Function, Method, Callsite, Symbol, UnknownTarget | L1 | Structure-complete symbols; UnknownTarget = unresolved callee |
| ResolutionNode, CFGBlock, SSAVariable, PHINode | L1–L3 | Semantic summaries |
| Entrypoint (Route, AjaxAction, HookRegistration) | L2 | WordPress surfaces |
| HookRegistration, Route, AjaxAction, CapabilityCheck, NonceGuardApprox | L2 | WordPress surface |
| Source | L3 | Untrusted input site (kind, context hint) |
| Sink | L4 | Dangerous consumer (kind: SQL, HTML, REDIRECT, FILE_INCLUDE, …) |
| Sanitizer | L3 | Known mitigation call site (context, name) |
| HeuristicPattern | L3 | Pattern lifted for rules (no direct file reads in evaluators) |
| SecuritySignal | L4 | Advanced security stubs |

## Relationship kinds (non-exhaustive)

- `IN_SNAPSHOT`, `CONTAINS_IR`, `HAS_HOOK`, … — structural
- `HAS_SOURCE`, `HAS_SINK`, `HAS_SANITIZER` — File → fact
- `FLOWS_TO`, `CAN_REACH_SINK`, `TAINTS` — flow approximations
- `HANDLED_BY`, `IMPLEMENTS_AJAX` — WordPress wiring

## Unknown / approximation

- `CALLS_UNKNOWN` edges must terminate on an `UnknownTarget` node (integrity requirement).
- Same-file `FLOWS_TO` uses **nearest source above sink** (not full Cartesian product); cap via `analysis.max_same_file_flow_edges_per_file`.
- Sinks are lifted from **IR labels** and **include/require IR kinds** (`include_expression`, etc.), not only `Callsite` nodes.
- Sink nodes may carry `static_arg` / `static_path_likely` for static include/read heuristics.
- WordPress semantics (`wp_import`) scan **IRNode** text via `CONTAINS_IR`, not structural node names alone.
- Edges may carry `approx: true`, `via`, `constraint_strength`.
- Unresolved dynamic behavior should be modeled as explicit graph nodes/edges where possible; otherwise witness `analysis_limits` must list the gap.

## Rules

- Each `RuleSpec` may set `min_graph_schema_version` (default `1`). The runner skips rules when the live graph schema sorts below the requirement, with telemetry `RULE_SKIPPED_SCHEMA`.

## Neo4j and vectors

- **Neo4j** is reserved for optional persistence and Cypher analytics — **not** a vector database. Semantic search embeddings belong in a dedicated vector store (e.g. Qdrant) in a later milestone.
