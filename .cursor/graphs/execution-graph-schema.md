# Execution Graph Schema (CFG-Oriented)

## Purpose
Approximate **control-flow reachability** to refine semantic findings: determine whether sanitizers conditionally guard sinks, identify unreachable defensive checks, and prioritize feasible paths.

## Node Types
- `:BasicBlock` — IR-level basic block id tied to `Function`/`Method`
- `:Guard` — predicates representing capability checks, nonces, `is_admin()`, etc. when detected
- `:CFGEdge` — represented as relationships `NEXT`, `TRUE_BRANCH`, `FALSE_BRANCH`, `EXCEPTION_EDGE` (policy-dependent)

## Relationships
- `(Symbol:Function)-[:ENTRY]->(BasicBlock)`
- `(BasicBlock)-[:NEXT|TRUE_BRANCH|FALSE_BRANCH]->(BasicBlock)`
- `(Guard)-[:GUARDS]->(BasicBlock|Callsite)` — approximation; may be conservative

## Construction Notes
CFG may be **partial** for dynamic PHP features; mark functions with `cfg_completeness` (`FULL`, `PARTIAL`, `NONE`).

## Traversal Patterns
- **Reachability with guards**: path exists from entry to sink block crossing at least one `Guard` of family `CAPABILITY`.
- **Dead defense detection**: guard blocks not on any path from relevant entry contexts.

## Interaction With Taint Graph
Combine **DATAFLOW** summaries with **CFG reachability** to reduce false positives where sanitizers exist only on unreachable branches.

## Confidence Derivation
- Full CFG + witness path elevates confidence when guards are contextually appropriate.
- Partial CFG applies penalties unless corroborated by dynamic tests.

See `execution-graph-starter.cypher`.
