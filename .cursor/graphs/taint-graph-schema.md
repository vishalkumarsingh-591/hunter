# Taint Graph Schema

## Purpose
Model **information flow** from untrusted sources to dangerous sinks with explicit sanitizer/transformer nodes.

## Node Types
- `:Source` — `kind` (`HTTP_PARAM`, `REST_BODY`, `META_UNTRUSTED`, …), `confidence`
- `:Sink` — `kind` (`SQL`, `HTML`, `JS_CONTEXT`, `SHELL`, `FILE_WRITE`, `DESERIALIZE`, `HTTP_OUTBOUND`)
- `:Sanitizer` — `name`, `contexts[]` it is valid for
- `:Transform` — ambiguous functions (e.g., `base64_decode`) modeled conservatively
- `:TaintRegion` — abstract regions binding AST spans for summarization

## Relationships
- `(Source)-[:TAINTS {label_set}]->(Symbol|Callsite|TaintRegion)`
- `(Symbol|Callsite)-[:FLOWS_TO {via:'assign'|'call_arg'|'return'|'field'}]->(...)`
- `(Sanitizer)-[:FILTERS {context}]->(TaintRegion|Callsite)`
- `(Transform)-[:MAY_INCREASE_UNCERTAINTY]->(TaintRegion)`

## Propagation Logic (Conceptual)
1. Initialize seeds at recognized sources per threat profile.
2. Expand along **FLOWS_TO** edges until fixpoint or limits.
3. Intersect paths with **FILTERS**; context mismatch ⇒ taint remains.

## Traversal Patterns
- **All paths**: bounded depth BFS with pruning on repeated `(node,label_set)` states.
- **Witness path extraction**: shortest witness with lexicographic ordering for stable reporting.

## Confidence Interaction
- Missing sanitizer on any witness path → strong positive feature for vulnerability hypotheses.
- Partial resolution of dynamic calls → uncertainty flags lowering confidence.

## Anti-Patterns
- Collapsing all sanitizers into one node without context edges.

See `taint-graph-starter.cypher`.
