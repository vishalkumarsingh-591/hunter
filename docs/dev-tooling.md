# Development tooling

## Linting

This project uses **Ruff** only (`[tool.ruff]` in `pyproject.toml`, optional `dev` extra). It is intentionally minimal (E/F/I/UP) and not a runtime dependency. Keep it unless the team explicitly removes lint tooling.

## Graph-first analysis

See [docs/graph-models/fact-graph-contract.md](graph-models/fact-graph-contract.md). Rule evaluators must not read plugin source files; facts live in the in-memory graph.

## Neo4j and vectors

Neo4j is optional for schema metadata only. Vector search belongs in a dedicated store in a future milestone — not Neo4j.
