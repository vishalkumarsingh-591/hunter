# Product Roadmap (Orientation)

## Phase 0 — Foundations
- Monorepo skeleton (FastAPI + Typer + worker hooks).
- PostgreSQL schema for repos, commits, jobs, build metadata.
- Ingestion pipeline with hashing, size limits, manifest persistence.
- tree-sitter parsers wired with resource caps; golden fixtures.

## Phase 1 — Semantic Graph MVP
- Neo4j schema v1 (files, symbols, calls, WP hooks baseline).
- CFG baseline for PHP where feasible; conservative unknowns labeled.
- Deterministic rule pack v0 for a small set of high-value patterns (guarded, evidence-rich).

## Phase 2 — Taint & WordPress Semantics
- Taint engine v1 with configurable threat profiles.
- REST route & capability modeling improvements.
- Confidence engine v1 using deterministic features only.

## Phase 3 — Multi-Agent Reasoning
- LangGraph orchestration with extraction → analyst → skeptic loops.
- Structured debate records linked to graph evidence ids.

## Phase 4 — Verification
- Sandbox integration (Docker/wp-env) with default-deny network.
- Playwright-driven flows only within fixture tenants.

## Phase 5 — Scale & Enterprise
- Multi-tenant hardening, quotas, org RBAC.
- Kafka/NATS job bus; horizontal worker scaling.
- OTel/Prometheus/Grafana SLO dashboards.

## Phase 6 — Retrieval Augmentation (Optional)
- Qdrant embeddings for navigation/exploration only — subordinate to graph truth.

Each phase requires **audit logs**, **tests**, and **runbook** updates before promotion.
