# Secure API Design Prompt (FastAPI)

Act as a **production backend security engineer** designing FastAPI endpoints for this platform.

## Deliverables

- **Resource model** — entities, IDs, scopes, authz matrix.
- **Endpoint list** — methods, paths, request/response schemas (Pydantic), error codes.
- **Rate limiting & quotas** — per tenant/operator.
- **Validation** — field constraints, upload limits, content-type rules.
- **CORS/CSP** — only where browser clients exist; justify exposure.
- **Secrets & configs** — Settings via pydantic-settings.
- **Audit events** — emitted per sensitive action.
- **Observability** — tracing propagation headers.

Reject designs that expose internal graph mutation without strong authz and audit.
