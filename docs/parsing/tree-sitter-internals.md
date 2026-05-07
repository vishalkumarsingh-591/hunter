# Parser Internals (Tree-sitter)

## Pipeline Stages
1. Language detection heuristic → confirmed by grammar trial.
2. Parse → CST nodes with byte ranges.
3. Lift → internal IR nodes + symbol tables.
4. Diagnostics → structured errors with taxonomy.

## Resource Governance
Hard caps prevent malicious quadratic blowups; configurable per tenant SLA tier.

## Multi-Language Repositories
PHP, JS, and HTML templates coexist — maintain per-file language binding rather than repo-wide assumption.

## WordPress Considerations
Detect PHP files with mixed HTML; optionally delegate regions to HTML grammar where policy enables.

## Version Pinning
Lock grammar revisions in CI; bump requires golden updates.

## Failure Observability
Emit metrics by error code; sample failing excerpts internally for developer review (not automatic customer exposure).

## Security
Parsing never executes code; extraction paths hardened against zip-slip and symlink escapes at ingestion layer.

Also see `.cursor/memory/parsing-standards.md`.
