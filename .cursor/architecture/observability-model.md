# Observability Model

## Correlation Strategy
- **trace_id**: spans entire user-initiated job from API/CLI entry.
- **build_id**: graph construction execution.
- **snapshot_id**: immutable Neo4j dataset produced by a build.

## Logging
Structured JSON logs with:
- `timestamp`, `level`, `service`, `trace_id`, `build_id`, `tenant_id` (if any)
- `event_type` enumerations (`INGEST_START`, `PARSE_FAIL`, `GRAPH_TX_COMMIT`, `AGENT_TOOL_CALL`, …)
- No sensitive payloads by default.

## Metrics (Starter Set)
- Ingest duration / bytes processed
- Parse success/fail counts by language
- Graph write throughput & transaction retries
- Rule evaluations/sec
- Agent token usage & tool latency
- Verification pass/fail/inconclusive rates

## Tracing
OpenTelemetry spans around:
- HTTP handlers
- Parser invocations
- Neo4j queries (sanitized statements as templates)
- LLM calls (vendor spans child of agent span)

## Dashboards & Alerts
Alert on sustained parser failure rates, Neo4j latency SLO breaches, stuck jobs, sandbox escapes (future detectors).

## Audit Trail Distinction
Audit events are **immutable append-only** logical streams suitable for compliance review, separate from debug logs.
