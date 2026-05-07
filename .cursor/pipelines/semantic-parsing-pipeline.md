# Semantic Parsing Pipeline

## Objective
Parse **all eligible files** into IR + diagnostics suitable for graph construction.

## Inputs
- Normalized file manifest from ingestion.
- Parser profile (languages enabled, limits).

## Outputs
- Per-file IR bundles (`ast_nodes.jsonl` or equivalent binary format).
- Unified diagnostics stream (`PARSE_SKIPPED`, `PARSE_ERROR`).
- Parser provenance record (`grammar_lock_hash`).

## Validation Logic
- Schema validate IR; reject files exceeding limits early.
- Require stable ordering for deterministic merges.

## Failure Handling
- File-level isolation: one failure does not abort entire batch unless critical path file defined by policy.
- Dead-letter queue for repeatedly failing paths with developer attention tags.

## Logging Requirements
Per-language counters; include example diagnostic capped at N per minute to avoid log storms.

## Observability Hooks
Histogram of parse latency per MB; error rate by language.

## Audit Requirements
Optional: record counts only — avoid storing full source in logs.
