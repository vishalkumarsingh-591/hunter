# Evidence Generation

## Definition
**Evidence** is machine-checkable linkage from a claim to repository and graph artifacts: node ids, relationship paths, byte spans, rule ids, and build metadata.

## Minimum Evidence Bundle
- `repo_id`, `commit_sha`, `build_id`, `snapshot_id`
- `rule_id` or `traversal_id`
- `anchors[]` with file path + offsets or stable node references
- `witness_path` summary for taint/CFG claims
- `parser_grammar_hash`, `rule_pack_hash`

## Provenance Chain
Evidence must cite **which deterministic stage** produced each anchor. LLM prose appended later cannot substitute missing anchors.

## Integrity
Store cryptographic hashes of excerpt payloads included in reports to detect tampering.

## Redaction
Secrets replaced deterministically with placeholders; hashes of originals optionally retained under restricted ACL (policy-bound).

## Reproducibility Appendix
Reports enumerate tooling versions and commands (where safe) to replay static portions.

## QA Checks
Automated validator rejects publishing-tier records missing mandatory fields.
