# Route Reachability Graph Schema

## Purpose
Unify **HTTP surfaces** (REST, AJAX, admin POST actions, front controllers) into a graph suitable for answering: “Which routes expose which handlers under which auth semantics?”

## Node Types
- `:HttpRoute` — `method`, `path_template`, `namespace`, `handler_symbol`, `permission_callback_kind`
- `:AjaxAction` — `action_name`, `nopriv` flag (`wp_ajax_nopriv_*`), handler binding
- `:AdminPage` — slug references (`add_menu_page`, …)
- `:Middlewareish` — shared guards (nonce checks) linked when identifiable

## Relationships
- `(HttpRoute)-[:HANDLED_BY]->(Symbol)`
- `(AjaxAction)-[:HANDLED_BY]->(Symbol)`
- `(HttpRoute)-[:REQUIRES_AUTH]->(ActorPattern)` — abstract patterns, not concrete users
- `(HttpRoute)-[:PUBLIC]->()` marker when explicitly unauthenticated
- `(HttpRoute)-[:CHAIN_BEFORE]->(HttpRoute)` — rare; for route stacking approximations

## Construction Sources
- REST: static patterns registering `register_rest_route`.
- AJAX: string literals in `wp_ajax_*` hook names.

## Traversal Patterns
- Enumerate all `PUBLIC` routes linked to sinks without sanitizers.
- Compare REST permission callbacks across versions for regressions (future differential builds).

## Confidence Derivation
- Static registration yields high confidence on existence of route.
- Actual runtime availability may differ (plugins conditional on options) — model conditional edges with `predicate_unknown=true` flag.

See `route-reachability-graph-starter.cypher`.
