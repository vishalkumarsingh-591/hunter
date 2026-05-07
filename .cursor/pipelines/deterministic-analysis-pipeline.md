# Deterministic Analysis Pipeline

## Objective
Emit **candidate findings** using rules, traversals, and taint — without LLM involvement.

## Inputs
- `snapshot_id`, `rule_pack_hash`, threat profile id.

## Outputs
- Candidate finding records with deterministic ids.
- Rule execution telemetry (`RULE_EVAL_COUNT`, `RULE_TIME_MS`).

## Validation Logic
- Each candidate must include anchors resolvable in graph.
- De-duplicate using canonical keys.

## Failure Handling
- Rule timeouts per rule class; mark candidates as `EVAL_SKIPPED` internally, not silent drops.

## Logging Requirements
Trace correlation per batch shard.

## Observability Hooks
Dashboards for rule hotspots and regression detection vs golden outputs.

## Audit Requirements
Store immutable mapping `rule_pack_hash → outputs_digest` for reproducibility queries.
