# Verification Pipeline

## Objective
Confirm/refute hypotheses using **static alternates** and optional **sandboxed dynamic** methods.

## Inputs
- Prioritized hypotheses + verification profiles + sandbox tickets (if dynamic).

## Outputs
- `verification_status` per hypothesis with artifact bundle references.

## Validation Logic
- Static jobs must complete deterministically on same snapshot inputs.
- Dynamic jobs require policy tokens + network egress denied unless explicit allowlist entry recorded in audit.

## Failure Handling
- Sandbox timeouts produce `INCONCLUSIVE` with captured logs.
- Infrastructure failures distinct from security inconclusiveness — separate error codes.

## Logging Requirements
Redacted stdout/stderr pointers; never store secrets.

## Observability Hooks
Track sandbox startup latency, CPU/mem ceilings, failure taxonomy.

## Audit Requirements
Immutable events for sandbox lifecycle and operator approvals.
