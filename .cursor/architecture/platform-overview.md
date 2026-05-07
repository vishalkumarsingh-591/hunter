# Platform Overview

This platform implements the pipeline:

**Deterministic Analysis → Knowledge Graph → Candidate Findings → Multi-Agent Reasoning → Skeptic Validation → Verification → Confidence Scoring → Reporting**

## Component Map
| Layer | Responsibility | Primary Tech |
|-------|----------------|--------------|
| Ingestion | Source acquisition, manifest, integrity | Python, object storage (future) |
| Parsing | tree-sitter lifts, IR, CFG fragments | tree-sitter-* |
| Graph Construction | Merge IR into Neo4j snapshot | Neo4j, batch writers |
| Deterministic Analysis | Rules, traversals, taint | Python + Cypher |
| Agents | Hypothesis + critique + scheduling | LangGraph, LLM APIs |
| Verification | Static/dynamic corroboration | Sandbox (future), tests |
| Confidence | Calibrated scoring | Feature models |
| Reporting | Evidence bundles | Markdown/JSON |

## Cross-Cutting Concerns
- **PostgreSQL** stores operational and forensic metadata.
- **Observability** spans all layers with shared correlation IDs.
- **Security** policy gates dangerous actions.

## Non-Goals (Architecture-Level)
- Real-time mass scanning of arbitrary internet targets.
- Autonomous exploit deployment.

## Reading Order
1. `.cursor/memory/architecture-principles.md`
2. `.cursor/pipelines/` docs
3. `.cursor/graphs/` schemas
4. `docs/architecture/` deeper ADRs as they appear
