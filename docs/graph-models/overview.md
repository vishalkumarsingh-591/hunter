# Graph Models Overview

The platform’s intelligence is **graph-native**: security questions are expressed as **pattern matching and reachability** over typed relationships.

## Family of Graphs
- **Semantic graph** — structure, calls, hook registrations.
- **Taint graph** — information flow with sanitizer context.
- **Execution graph** — CFG approximations and guard placement.
- **Trust boundary graph** — actors, entrypoints, assets, zones.
- **Capability inheritance graph** — roles, capabilities, checks.
- **Route reachability graph** — HTTP/REST/AJAX exposure.

## Cross-Graph Linking
Nodes share stable keys (e.g., `Callsite.id`, `Symbol.fqn` scoped to build). Projections may materialize merged views for specific algorithms.

## Versioning
Each snapshot stores `SchemaMeta` describing label/rel versions. Migrations are explicit, not implicit.

## Query Discipline
Pre-approved Cypher templates with parameter binding only — no string interpolation from untrusted input.

## Further Reading
- `.cursor/graphs/README.md` and individual `*-schema.md` files
- `docs/taint-analysis/methodology.md` for flow semantics
