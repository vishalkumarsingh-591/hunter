# Trust Boundary Graph Schema

## Purpose
Encode **who** can reach **what** under **which assumptions**, bridging HTTP surfaces, WP roles, authentication state, and sensitive operations.

## Node Types
- `:Actor` — `kind` (`UNAUTHENTICATED`, `SUBSCRIBER`, `CONTRIBUTOR`, `AUTHOR`, `EDITOR`, `ADMIN`, `CUSTOM_ROLE:{name}`)
- `:Entrypoint` — REST route, admin page hook, `wp_ajax_*`, public callback
- `:Asset` — capability-changing operations, option writes, user meta writes, SQL exec sites
- `:TrustZone` — grouping (`PUBLIC_HTTP`, `ADMIN_CP`, `CLI`, `CRON`)

## Relationships
- `(Entrypoint)-[:IN_ZONE]->(TrustZone)`
- `(Actor)-[:MAY_INVOKE {conditions}]->(Entrypoint)` — conservative edges labeled with uncertainty
- `(Entrypoint)-[:ACCESSES]->(Asset)`
- `(Asset)-[:CROSS_BOUNDARY_FROM]->(TrustZone)` — explicit crossing for reporting

## Semantics
Edges carry **evidence pointers** to capability checks (or their absence). Absence is modeled explicitly, not as missing data only.

## Traversal Patterns
- Find paths `(UNAUTHENTICATED Actor)-[:MAY_INVOKE*..3]->(Entrypoint)-[:ACCESSES]->(Asset {sensitivity:'HIGH'})`.
- Identify **trust boundary violations** when low-trust actors reach high-sensitivity assets without mitigating guards.

## Confidence Derivation
- Strong when REST `permission_callback` literals resolve to capability maps.
- Weak when dynamic permission logic prevents static proof — requires dynamic verification or manual review.

See `trust-boundary-graph-starter.cypher`.
