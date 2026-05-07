# Capability Inheritance Graph Schema

## Purpose
Model **WordPress roles and capabilities** as a directed graph to reason about privilege assumptions and escalation chains.

## Node Types
- `:Role` — canonical WP roles + custom roles discovered via static references (`install_plugins`, `edit_users`, …)
- `:Capability` — string nodes normalized (`install_plugins`, `manage_options`, …)
- `:Check` — callsites invoking `current_user_can`, `user_can`, `map_meta_cap` filters (approximated)

## Relationships
- `(Role)-[:GRANTS]->(Capability)`
- `(Role)-[:INHERITS {approx:true}]->(Role)` — only when statically evidenced or via curated WP defaults graph versioned externally
- `(Check)-[:ASSERTS]->(Capability)`
- `(Symbol|Entrypoint)-[:REQUIRES]->(Capability)` — when derived from permission callbacks or manual annotations

## Static Approximation Policy
WordPress default role-capability maps should be **versioned datasets**, not hard-coded scattered literals. Graph stores dataset reference `wp_role_model_version`.

## Traversal Patterns
- Determine if a handler **requires** capability C while another reachable path grants **custom role** unexpected `GRANTS` edges (plugin-defined).
- Escalation candidates: `(LowRole)-[:GRANTS]->(HighSensitivityCapability)` without matching WP defaults — flag as plugin customization with analyst review.

## Confidence Derivation
- High when checks statically bind string literals.
- Low when capabilities computed dynamically — escalate skeptic review.

See `capability-inheritance-graph-starter.cypher`.
