# Reporting Pipeline

## Objective
Produce **evidence-backed** human and machine-readable reports suitable for audit.

## Inputs
- Finalized hypotheses + scores + redaction policy + branding settings.

## Outputs
- `report_id`, exported bundles, integrity hashes (and signatures if enabled).

## Validation Logic
- Ensure every narrative paragraph maps to structured fields.
- Verify excerpts belong to manifest spans.

## Failure Handling
- Report generation retries on transient storage errors; idempotent on `report_id`.

## Logging Requirements
Publication events with recipient scope (internal/external).

## Observability Hooks
Latency to generate; export size metrics.

## Audit Requirements
Signer identity, approval chain references, retention class.
