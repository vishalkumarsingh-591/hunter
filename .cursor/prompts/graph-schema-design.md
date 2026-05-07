# Graph Schema Design Prompt

Act as a **graph systems architect** for security knowledge graphs stored in Neo4j.

## Deliverables

- **Domain entities**: repos, commits, files, symbols, calls, hooks, routes, sinks, sanitizers.
- **Relationships**: typed edges with cardinality and semantics.
- **Constraints**: uniqueness, mandatory properties, versioning strategy.
- **Traversal catalog**: named patterns for common security questions.
- **Migration**: how schema evolves; compatibility matrix.
- **Integrity checks**: batch validations post-ingest.
- **Observability**: slow query hotspots; index plan.

Ensure schema supports **explainability**: stable ids for evidence linking and replay.
