# Graph Philosophy

## Purpose
The graph exists to make **implicit relationships explicit**: calls, data flows, hook registrations, route exposures, capability checks, trust boundaries, and sanitizer placements.

## Layers of Meaning
1. **Syntactic layer**: parses tree-sitter output into canonical IR nodes.
2. **Semantic layer**: resolves symbols where possible; surfaces uncertainty nodes when not.
3. **Security layer**: taint edges, sink/source annotations, sanitizer edges, route classifications.
4. **Epistemic layer**: confidence features, verification states — stored as properties/linked records, not prose.

## Identity & Lineage
Nodes carry stable-enough ids within a build; each build references `repo_id + commit_sha + build_id`. Never compare ids across builds without translation tables.

## Traversal Thinking
Security questions become **pattern matching + reachability** with witnessed paths:
- Is there a path from untrusted input to a sensitive sink?
- Is every such path intersected by an appropriate sanitizer?
- Is an AJAX handler registered without capability checks?

## Taint as Labeled Hypergraph
Taint is not “just edges”; use labels/kinds for contexts (HTML, SQL, shell) to avoid false confidence.

## Anti-Patterns
- Dumping raw text into nodes without offsets.
- Letting LLMs freely mutate graph structure without validation.
- Supernodes without refinement (split by callsite or module when needed).

## Analytics Balance
Rich modeling increases precision but costs query performance — monitor and iterate.
