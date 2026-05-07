# Engineering Conventions

## Naming
- **Python modules**: `snake_case` files; packages short and domain-oriented (`ingest`, `parse`, `graph`, `analyze`, `agents`, `verify`, `report`).
- **Pydantic models**: `PascalCase`; fields `snake_case`.
- **Graph labels**: `PascalCase` singular (`:File`, `:Function`); relationships `UPPER_SNAKE` (`CALLS`, `TAINTS`).
- **Rule IDs**: `RULE-<DOMAIN>-<nnn>` (e.g., `RULE-SQLI-014`).

## Repository Layout (Recommended)
```
src/
  hunter/                 # importable package root (example)
    api/                  # FastAPI routers, deps
    cli/                  # Typer apps
    ingest/
    parse/
    graph/
    analysis/
    agents/
    verify/
    reporting/
    observability/
tests/
fixtures/
docs/
```

## Time & IDs
- UTC timestamps in APIs/logs.
- **UUIDv7** or ULIDs for external IDs where sortability helps; internal Neo4j ids are implementation-specific and never exposed without snapshot binding.

## Configuration
- Environment-specific `.env` only local; production uses secret stores.
- `Settings` class validates all URLs and tokens at startup.

## Error Handling
- Domain exceptions mapped to HTTP errors in API layer only.
- Never return raw exception strings to external clients.

## Documentation
- ADRs for major decisions (`docs/architecture/adr/` optional future).
- Update `.cursor/memory/` when stack-wide conventions change.

## AI Outputs
- Always validate JSON from models against schemas before use.
- Store **evidence handles**, not unbounded prose, in durable finding records.
