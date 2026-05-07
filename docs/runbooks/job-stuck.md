# Runbook: Job Stuck / Pipeline Stall

## Symptoms
- Job status `RUNNING` beyond SLA.
- Queue depth increasing without worker consumption.

## Preconditions
- Confirm incident correlation id / `trace_id`.
- Identify affected stage (`INGEST`, `PARSE`, `GRAPH`, `ANALYZE`, `AGENTS`, `VERIFY`, `REPORT`).

## Steps
1. **Verify worker health** — process up, correct env vars, DB connectivity.
2. **Inspect logs** for repeated failures masked as retries.
3. **Check Neo4j** — long-running transactions or lock contention; capture slow query log samples (sanitized).
4. **Database locks** — Postgres advisory locks for dedup keys if used.
5. **Cancel job** if safe — triggers compensating cleanup per policy.
6. **Replay** job idempotently after fix.

## Escalation
Engage graph + infra owners if Neo4j instability persists.

## Post-Incident
Add regression metric/alerts; document bug ticket links.
