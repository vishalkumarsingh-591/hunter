# Multi-Agent Reasoning Pipeline (LangGraph)

## Objective
Refine, contextualize, and prioritize deterministic candidates using bounded agent graphs.

## Inputs
- Candidate bundles + subgraph exports + policy config.
- Orchestration state schema version.

## Outputs
- Annotated hypotheses, critiques, scheduling decisions for verification.
- Checkpointed LangGraph state for resumability.

## Validation Logic
- Schema validation on every agent output.
- Tool argument allowlisting; maximum recursion depth.

## Failure Handling
- Budget exhaustion triggers graceful degradation: emit partial annotations + explicit uncertainty.
- Poisoned tool responses retry once then abort branch.

## Logging Requirements
Span per node; aggregate token usage; no chain-of-thought persistence.

## Observability Hooks
Metrics for agent error rates, retries, tool latency.

## Audit Requirements
Record model ids, prompt template hashes, and operator overrides.
