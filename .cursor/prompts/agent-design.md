# Agent Design Prompt (LangGraph)

Design a **specialized agent** for this platform.

Include:

- **Mission** — narrow scope; forbidden scope creep.
- **Inputs** — typed state slices; max token budgets.
- **Tools** — explicit allowlist with schemas; timeouts.
- **Outputs** — Pydantic-validated artifacts referencing evidence ids.
- **Hallucination safeguards** — mandatory citations to graph nodes/paths or deterministic summaries.
- **Interaction pattern** — which other agents it may call and under what conditions.
- **Failure behavior** — partial results with uncertainty flags.
- **Audit** — what gets logged; no secret leakage.

Default stance: agents **annotate and prioritize** deterministic findings; they do not invent vulnerabilities.
