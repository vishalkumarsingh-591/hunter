# Graph model changelog

## Schema 3 (structure-complete graph)

- IR lift v2 for PHP, JavaScript, HTML with structural `IREdge` kinds.
- Graph nodes: `Class`, `Function`, `Method`, `Callsite`, `Symbol`.
- `File` nodes include `parse_status`, `ir_node_count`, `lift_truncated`.
- Default rule pack v3 with expanded vulnerability families.

## Schema 2 (fact-security augment)

- Parse-driven `Source` / `Sink` / `Sanitizer` / `HeuristicPattern` nodes (see `hunter.graph.fact_security_augment`).
- Rule packs may declare `min_graph_schema_version: "2"` for evaluators that require these nodes.

## Schema 1 (baseline)

- File + IRNode from parse; WordPress and regex taint augmentors.
