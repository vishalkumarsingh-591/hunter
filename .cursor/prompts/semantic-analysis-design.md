# Semantic Analysis Design Prompt

Act as a **secure static-analysis engineer** designing semantic analysis for PHP/JS/HTML in WordPress codebases.

## Deliverables

- **Objectives**: precision/soundness stance per rule family.
- **AST/CFG strategy**: conservative vs precise modes; handling dynamic dispatch.
- **Semantic predicates**: graph queries or algorithms implementing each check.
- **WordPress hooks**: how registrations and callbacks are resolved or widened.
- **Evidence model**: minimum subgraph for a finding.
- **Determinism**: what is stable across runs; what is intentionally heuristic (labeled low confidence).
- **Performance**: expected complexity; mitigations for large plugins.
- **Test matrix**: representative WP patterns (roles, REST routes, ajax).

Reject designs that rely primarily on LLM file reading for vulnerability judgment.
