# Technology Stack

## Core Runtime & Services
- **Python** (3.11+ recommended): primary implementation language.
- **FastAPI**: HTTP APIs, OpenAPI-first contract.
- **Typer**: operator/analyst CLI for batch jobs and maintenance.
- **Pydantic v2 / pydantic-settings**: configuration and strict DTO boundaries.

## Orchestration & AI
- **LangGraph**: explicit multi-agent workflows with checkpointed state.
- **OpenAI-compatible APIs / local LLMs**: hypothesis assistance only after deterministic grounding (policy-enforced).

## Persistence & Graph
- **PostgreSQL**: transactional metadata (repos, jobs, users/tenants, audit events, report indexes).
- **Neo4j**: canonical knowledge graph for multi-hop security reasoning.
- **NetworkX**: algorithm prototyping / offline analytics; export paths to Neo4j for production workflows.

## Future Vector Retrieval
- **Qdrant**: semantic retrieval over embeddings of symbols/docs — optional future stage; must not replace graph evidence for findings.

## Parsing & Analysis
- **tree-sitter-php**, **tree-sitter-javascript**, **tree-sitter-html**: syntactic foundation.
- Internal layers: AST enrichment, CFG construction, taint engine, semantic rule engine.

## Observability & Ops (target state)
- **OpenTelemetry**, **Prometheus**, **Grafana**, structured logging with correlation IDs.

## Dynamic Verification (future)
- **Docker**, **wp-env**, **Playwright** inside locked-down sandboxes; default-deny egress.

## Scale-out (future)
- **Kubernetes**, **Ray** (CPU farms for batch analysis), **Kafka/NATS** for job buses.
- **Terraform** for IaC.

## Engineering Invariants
- Deterministic stages produce **evidence ids** consumed by agents.
- LLMs never hold sole authority over severity or exploitability claims.
