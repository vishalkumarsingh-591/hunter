# REST API Standards (FastAPI)

## Design Tenets
- Schema-first via Pydantic models mirrored into OpenAPI.
- Explicit auth schemes (`Bearer`, API keys) — choose per deployment.
- Idempotent mutations where feasible (`Idempotency-Key` header pattern).

## Error Model
Return structured errors:
```json
{
  "error": {
    "code": "GRAPH_SNAPSHOT_NOT_FOUND",
    "message": "Snapshot does not exist",
    "correlation_id": "…"
  }
}
```
Never leak stack traces externally.

## Pagination & Limits
Cursor-based pagination for large lists; `limit` caps enforced server-side.

## Observability
Emit `traceparent` compatible headers; log `correlation_id`.

## Security
- Rate limit per tenant/API key.
- Validate content types and payloads strictly.
- Avoid exposing internal Neo4j constructs directly — use projection DTOs.

## Documentation
Publish generated OpenAPI under `docs/api/openapi.yaml` when the implementation exists.
