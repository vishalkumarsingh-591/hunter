from __future__ import annotations

from pathlib import Path

from hunter.agents.deterministic import deterministic_hypothesis, deterministic_skeptic
from hunter.confidence.engine import ConfidenceEngine
from hunter.models.findings import CandidateFinding, EnrichedFinding
from hunter.verify_static.engine import verify_finding


def enrich_findings(
    candidates: list[CandidateFinding],
    *,
    scan_id: str,
    graph_integrity_ok: bool,
    agents_enabled: bool,
    confidence_weights: Path | None = None,
    profile_id: str = "",
) -> tuple[list[EnrichedFinding], list[dict]]:
    if agents_enabled:
        from hunter.agents.workflows.scan_workflow import run_langgraph_enrichment

        return run_langgraph_enrichment(
            candidates,
            scan_id=scan_id,
            graph_integrity_ok=graph_integrity_ok,
            confidence_weights=confidence_weights,
        )
    engine = ConfidenceEngine(confidence_weights, profile_id=profile_id)
    enriched: list[EnrichedFinding] = []
    trace: list[dict] = []
    for c in candidates:
        hyp = deterministic_hypothesis(c)
        sk = deterministic_skeptic(c)
        ver = verify_finding(c)
        conf = engine.score(c, ver, sk, graph_integrity_ok)
        enriched.append(EnrichedFinding(candidate=c, hypothesis=hyp, skeptic=sk, verification=ver, confidence=conf))
        trace.append(
            {
                "finding_id": c.finding_id,
                "step": "deterministic_pipeline",
                "hypothesis_hash": hyp.evidence_manifest_hash,
                "verification_status": ver.status,
            }
        )
    return enriched, trace
