# System Architecture

## Vision
This platform implements **repository-wide static semantic analysis** augmented by **multi-agent reasoning** while preserving **deterministic evidence** as the source of truth.

## Macro Pipeline
1. **Ingestion** normalizes repositories with integrity guarantees.
2. **Parsing** lifts syntax trees into an analyzable IR using tree-sitter.
3. **Graph construction** merges structural, taint, execution, trust-boundary, capability, and route graphs into a Neo4j snapshot.
4. **Deterministic analysis** emits candidate findings with reproducible ids.
5. **Agents** contextualize and prioritize candidates using bounded tools.
6. **Verification** corroborates or refutes hypotheses under strict policies.
7. **Confidence scoring** transparently merges quantitative signals.
8. **Reporting** emits audit-grade bundles.

## Key Stores
- **PostgreSQL**: tenancy, jobs, audit metadata, report indexes.
- **Neo4j**: analytical truth for multi-hop reasoning.

## Modularity
Services communicate via explicit APIs/events (future bus). Shared libraries hold schemas and graph projections — avoid cyclic imports across layers.

## Evolution
Dynamic verification and horizontal scaling are additive phases that **must not** weaken deterministic anchors.

See also: `.cursor/architecture/platform-overview.md`, `.cursor/architecture/layered-pipeline.md`.
