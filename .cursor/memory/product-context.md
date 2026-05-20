# Product Context

## Mission
Build an **agentic AI-powered PHP vulnerability research platform** (WordPress as flagship profile) for **authorized defensive security research**. The product prioritizes **high-confidence, explainable, evidence-backed** vulnerability insights over noisy scanning.

## What This Product Is
- A **semantic vulnerability analysis engine** grounded in repository-wide understanding.
- A **graph-driven research system** connecting code structure, platform semantics (WordPress profile), data flow, and trust boundaries.
- A **profile-driven** analyzer: `generic-php`, `wordpress`/`full`, and `auto` detect.
- A **multi-agent reasoning framework** where models assist under strict guardrails.
- An **audit-heavy** platform suitable for enterprise research workflows.

## What This Product Is Not
- A generic AI scanner or chatbot wrapper.
- A regex-only signature scanner (regex may assist, never rule alone for severity).
- A claim of complete OWASP Top 10 / commercial SAST parity.
- An exploit framework or autonomous attack system.
- A substitute for human judgment on legal/safety boundaries.

## Primary Users
- Vulnerability researchers, application security engineers, and platform defenders operating under explicit authorization.

## Initial Focus
- **Static semantic analysis** with whole-repository parsing, YAML security catalogs, and graph construction.

## Evolution Path
- **Dynamic verification** in sandboxed environments.
- **Additional language profiles** (e.g. JavaScript assets) via catalog + parse extensions.
- **Autonomous research** limited by policy, budgets, human gates, and skeptic/verification stages.

## Success Metrics (Orientation)
- Precision of high-severity findings (minimize false positives at top buckets).
- End-to-end explainability scores (human audit time reduction without sacrificing correctness).
- Reproducibility rate: same inputs → same deterministic artifacts.
- Operational metrics: ingest ↔ report latency at realistic repository sizes.

## Ethical Posture
Defensive disclosure aligned; minimize dual-use harm; no covert operational tooling features.
