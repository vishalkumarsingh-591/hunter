# Documentation Index

Authoritative engineering context for the WordPress vulnerability research platform lives alongside `.cursor/memory/` and `.cursor/architecture/`.

## Product & Architecture
- [System architecture](architecture/system-architecture.md)
- [Confidence scoring](architecture/confidence-scoring.md)
- [Evidence generation](architecture/evidence-generation.md)

## Domain Models
- [Graph models overview](graph-models/overview.md)
- [Taint methodology](taint-analysis/methodology.md)
- [WordPress security surfaces](wordpress-semantics/security-surfaces.md)

## Operations & Security Process
- [Platform threat model starter](threat-models/platform-threat-model.md)
- [Runbook: stuck jobs](runbooks/job-stuck.md)
- [Runbook: parser regression](runbooks/parser-regression.md)
- [Incident severity playbook](incident-response/severity-playbook.md)

## Interfaces & Workflows
- [REST standards](api/rest-standards.md)
- [Agent orchestration](agent-workflows/orchestration.md)
- [Verification workflows](agent-workflows/verification-workflows.md)

## Parsing
- [Tree-sitter internals](parsing/tree-sitter-internals.md)

## Cursor Project Brain
See `.cursor/rules/` for always-on engineering constraints and `.cursor/pipelines/` for stage contracts.
