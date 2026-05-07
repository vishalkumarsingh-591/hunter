# Layered Pipeline Architecture

## Boundary Contracts
Each stage consumes and produces **versioned DTOs**. Failure responses must be discriminated unions, not ambiguous nulls.

### Ingestion → Parsing
- Input: archive/git reference + policy profile.
- Output: normalized file tree descriptors + content-addressed blobs.

### Parsing → Graph
- Input: IR bundles per file + symbol tables.
- Output: graph upsert batch files or transactional Cypher.

### Graph → Analysis
- Input: snapshot id + rule pack hash.
- Output: candidate finding records (deterministic ids).

### Analysis → Agents
- Input: candidate bundles + bounded subgraph exports.
- Output: structured annotations (never raw severity changes without gates).

### Agents → Verification
- Input: hypotheses + artifact manifest.
- Output: verification results schema.

### Verification → Confidence
- Input: features + verification vectors.
- Output: calibrated scores + explanations.

### Confidence → Reporting
- Input: finalized records + redaction policy.
- Output: signed/hashed evidence bundles (policy-dependent).

## Backpressure
Long-running stages publish heartbeats; orchestrator applies concurrency limits per tenant.

## Idempotency
Re-running a stage with same inputs must not duplicate durable entities — use deterministic keys (`repo_id:commit:path:rule_id:anchor_node_id`).

## Extensibility
New rule families extend analysis without rewriting ingestion; new agents attach via LangGraph subgraphs with declared state slices.
