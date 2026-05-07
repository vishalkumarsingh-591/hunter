# Semantic Graph Schema

## Purpose
Represent **repository structure** and **program meaning** at the granularity needed for security reasoning: files, namespaces, classes, functions/methods, calls, constants, includes, and WordPress-specific registrations.

## Core Node Types
- `:Repository` — logical project (`id`, `slug`)
- `:Commit` — `sha`, `parents`, `timestamp`
- `:File` — `path`, `language`, `hash`, `bytes`
- `:Symbol` — functions/methods/classes; `kind`, `name`, `fqn`, `visibility`
- `:Callsite` — invocation sites; `resolved_target_fqn?`, `resolution_kind` (`STATIC`, `DYNAMIC`, `UNKNOWN`)
- `:HookRegistration` — WP `add_action` / `add_filter` with `hook_name`, `priority?`, `callback_resolution`
- `:Constant` / `:StringLiteral` (selective, for evidence anchors)

## Core Relationships
- `(File)-[:DEFINES]->(Symbol)`
- `(Symbol)-[:DECLARES]->(Symbol)` — nested scopes
- `(Callsite)-[:IN_FILE]->(File)`
- `(Callsite)-[:INVOKES]->(Symbol)` — when resolved
- `(Callsite)-[:INVOKES_UNRESOLVED]->(UnknownTarget)` — explicit uncertainty
- `(HookRegistration)-[:REGISTERS_CALLBACK]->(Symbol|Closure)`
- `(File)-[:IMPORTS|REQUIRES|INCLUDES {kind}]->(File|PathExpr)`

## WordPress Semantics
- Hook nodes link to **potential execution order** approximations via `(HookRegistration)-[:ATTACHES_TO_HOOK]->(:HookName)` nodes.

## Traversal Patterns
- **Callee closure**: expand callers/callees up to depth N with cycle guards.
- **Hook subscribers**: find all callbacks for `wp_ajax_*` style hooks when statically known.

## Confidence Derivation Hooks
- Higher confidence when call targets resolve statically.
- Penalize clusters of `UNKNOWN` resolutions adjacent to sinks.

## Starter Cypher
See `semantic-graph-starter.cypher` for constraints and sample motifs.

## Graph ↔ Deterministic Rules
Rules reference `(Callsite)` ids + `(Symbol)` ids + relationships — never filenames alone.
