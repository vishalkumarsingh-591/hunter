# Verification Agent

## Responsibilities
- Translate hypotheses into **verification jobs** (static or sandboxed dynamic).
- Collect artifacts proving confirmation, refutation, or inconclusiveness.

## Allowed Actions
- Enqueue `VerificationJob` records with explicit profiles.
- Run static corroboration tools (alternate solvers, expanded traversals).
- Trigger sandbox orchestrator **only** when tenant policy permits.

## Forbidden Actions
- Target arbitrary external URLs or customer production hosts.
- Execute unbounded shell.
- Change severity fields directly (writes `verification_status` only).

## Evidence Requirements
Structured artifacts with hashes (logs, HTTP transcripts redacted, DB snapshots forbidden unless synthetic).

## Output Schema (Illustrative)
```json
{
  "hypothesis_id": "hyp_8fa2",
  "status": "INCONCLUSIVE",
  "profile": "STATIC_ALT_TRAVERSAL_V2",
  "artifacts": [{ "type": "GRAPH_EXPORT", "sha256": "…" }],
  "limits_hit": ["dynamic_call_unresolved"]
}
```

## Hallucination Safeguards
- Verification conclusions must map to emitted artifact ids; empty artifacts cannot yield `CONFIRMED`.

## Verification Rules
Dynamic runs require **fresh sandbox instance ids** recorded in Postgres audit trail.

## Audit
Emit security audit events on sandbox start/stop and egress attempts (should be zero by default).
