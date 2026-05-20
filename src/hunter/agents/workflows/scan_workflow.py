from __future__ import annotations

from pathlib import Path

from langgraph.graph import END, StateGraph

from hunter.agents.graph_state import AgentState
from hunter.confidence.engine import ConfidenceEngine
from hunter.models.findings import CandidateFinding, EnrichedFinding
from hunter.verify_static.engine import verify_finding


def run_langgraph_enrichment(
    candidates: list[CandidateFinding],
    *,
    scan_id: str,
    graph_integrity_ok: bool,
    confidence_weights: Path | None = None,
) -> tuple[list[EnrichedFinding], list[dict]]:
    """LangGraph wiring; when agents_enabled, still no LLM for verification (per SRS)."""
    from hunter.agents.deterministic import (  # noqa: PLC0415
        deterministic_hypothesis,
        deterministic_skeptic,
    )

    def extract(s: AgentState) -> dict:
        trace = list(s.get("reasoning_trace") or [])
        trace.append({"step": "extract", "scan_id": s["scan_id"], "count": len(s["candidates"])})
        return {"reasoning_trace": trace}

    def analyst(s: AgentState) -> dict:
        trace = list(s.get("reasoning_trace") or [])
        trace.append({"step": "analyst", "mode": "deterministic_template"})
        return {"reasoning_trace": trace}

    def skeptic(s: AgentState) -> dict:
        trace = list(s.get("reasoning_trace") or [])
        trace.append({"step": "skeptic", "mode": "deterministic_rules"})
        return {"reasoning_trace": trace}

    def finalize(s: AgentState) -> dict:
        engine = ConfidenceEngine(confidence_weights)
        enriched: list[EnrichedFinding] = []
        for raw in s["candidates"]:
            c = CandidateFinding.model_validate(raw)
            hyp = deterministic_hypothesis(c)
            sk = deterministic_skeptic(c)
            ver = verify_finding(c)
            conf = engine.score(c, ver, sk, s["graph_integrity_ok"])
            enriched.append(EnrichedFinding(candidate=c, hypothesis=hyp, skeptic=sk, verification=ver, confidence=conf))
        trace = list(s.get("reasoning_trace") or [])
        trace.append({"step": "finalize", "count": len(enriched)})
        return {"enriched": [e.model_dump() for e in enriched], "reasoning_trace": trace}

    g = StateGraph(AgentState)
    g.add_node("extract", extract)
    g.add_node("analyst", analyst)
    g.add_node("skeptic", skeptic)
    g.add_node("finalize", finalize)
    g.set_entry_point("extract")
    g.add_edge("extract", "analyst")
    g.add_edge("analyst", "skeptic")
    g.add_edge("skeptic", "finalize")
    g.add_edge("finalize", END)
    app = g.compile()
    init: AgentState = {
        "scan_id": scan_id,
        "graph_integrity_ok": graph_integrity_ok,
        "agents_enabled": True,
        "candidates": [c.model_dump() for c in candidates],
        "reasoning_trace": [],
    }
    out = app.invoke(init)
    enriched_models = [EnrichedFinding.model_validate(x) for x in out.get("enriched", [])]
    return enriched_models, list(out.get("reasoning_trace") or [])
