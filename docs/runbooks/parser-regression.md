# Runbook: Parser Regression

## Symptoms
- Sudden spike in `PARSE_ERROR` or skipped files after upgrade.
- Golden tests failing in CI.

## Steps
1. Identify **grammar revision** delta vs last green build.
2. Bisect fixtures — isolate minimal failing file snippet.
3. Validate resource limits not falsely rejecting larger legitimate plugins.
4. Roll forward fix or temporarily pin grammar version with explicit ticket.
5. Update golden artifacts or migration notes.

## Communication
Notify analysis consumers that `snapshot_id` semantics may change across grammar bumps.

## Prevention
Require parser upgrade checklist from `.cursor/prompts/release-checklist.md`.
