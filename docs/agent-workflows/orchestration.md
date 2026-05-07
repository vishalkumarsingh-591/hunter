# Agent Workflow Orchestration

## LangGraph Topology (Conceptual)
```
extract ─► analyst ─► skeptic ─┬► verification ─► confidence ─► reporting
                               └► (loop back on unresolved critiques)
```

## State Schema
Typed dict or Pydantic model containing:
- `candidate_ids[]`
- `hypothesis_ids[]`
- `critiques[]`
- `verification_jobs[]`
- `budgets{}`

## Checkpointing
Persist checkpoints after each external side-effect boundary for resume safety.

## Governance Hooks
- Hard ceilings on tool calls and tokens.
- Automatic downgrade when skeptic blocks promotion.

## Observability
Each transition emits spans; correlate with `trace_id`.

## Safety
Untrusted repo text only enters via sanitized channels with policy preamble separating instructions from data.

See `.cursor/pipelines/multi-agent-reasoning-pipeline.md` and `.cursor/agents/*.md`.
