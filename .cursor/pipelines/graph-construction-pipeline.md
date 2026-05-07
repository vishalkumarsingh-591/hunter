# Graph Construction Pipeline

## Objective
Materialize versioned Neo4j snapshots linking semantic, taint, execution, and trust graphs.

## Inputs
- IR bundles + symbol resolution outputs.
- Schema version + migration scripts.
- `build_id` correlation.

## Outputs
- `snapshot_id` referencing immutable graph dataset.
- Integrity report (orphan edges, constraint violations).

## Validation Logic
- Post-load constraint checks; sampling traversals for smoke motifs.
- Cardinality alarms (unexpected explosion).

## Failure Handling
- Transaction batching with retries on deadlock; idempotent MERGE keys.
- Automatic rollback to empty partial state on catastrophic failure (no half-published snapshot).

## Logging Requirements
Batch commit milestones; summarize nodes/rels created.

## Observability Hooks
Neo4j query timing exporters; builder stage spans.

## Audit Requirements
Record operator/service identity triggering rebuild; link to prior snapshot for lineage.
