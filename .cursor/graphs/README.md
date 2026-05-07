# Graph Schemas Index

This directory defines **security-aware knowledge graph** models used by the platform. Each schema includes:

- Node types and properties
- Relationship types and semantics
- Traversal patterns for analysis
- Starter Cypher for constraints and example queries
- How **taint**, **confidence**, and **verification** link in

## Schemas
| Document | Purpose |
|----------|---------|
| `semantic-graph-schema.md` | Code structure, symbols, calls, WP hooks |
| `taint-graph-schema.md` | Sources, sinks, propagations, sanitizers |
| `execution-graph-schema.md` | CFG blocks, guards, approximate control flow |
| `trust-boundary-graph-schema.md` | Actors, entrypoints, data crossing boundaries |
| `capability-inheritance-graph-schema.md` | WP roles/caps static approximations |
| `route-reachability-graph-schema.md` | HTTP/REST/ajax route exposure |

**Version** all schema changes in metadata nodes (`:SchemaMeta`).
