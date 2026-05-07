# Repository Ingestion Pipeline

## Objective
Acquire source trees **safely** and reproducibly for downstream parsing.

## Inputs
- Source descriptor (`git_url+commit`, archive URI with approval, local path for dev-only).
- Policy profile (`max_bytes`, `max_files`, allowed extensions).
- Operator context (`tenant_id`, `trace_id`).

## Outputs
- `repo_id`, `commit_sha`, content-addressed blob references.
- `manifest.json` with file listing + hashes + parse hints.
- `ingest_status` enum (`SUCCESS`, `PARTIAL`, `FAILED`).

## Validation Logic
- Reject path traversal in archives.
- Enforce quotas before extraction completes.
- Verify commit exists for git sources.

## Failure Handling
- Retry transient network with jitter (git only).
- Surface actionable diagnostics; never partial-commit unclear states without labeling.

## Logging Requirements
Structured events: `INGEST_START`, `INGEST_MANIFEST_READY`, `INGEST_FAIL` with reasons.

## Observability Hooks
Metrics: duration, bytes, file counts, failure taxonomy counters.

## Audit Requirements
Append-only audit row per ingestion including actor and source provenance (non-secret).
