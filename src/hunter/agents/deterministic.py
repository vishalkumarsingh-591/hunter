from __future__ import annotations

import hashlib

from hunter.models.findings import CandidateFinding, HypothesisAnnotation, SkepticVerdict


def deterministic_hypothesis(f: CandidateFinding) -> HypothesisAnnotation:
    body = f"Deterministic summary for {f.rule_id}; anchors at lines {[a.start_line for a in f.anchors]}."
    h = hashlib.sha256(body.encode()).hexdigest()[:12]
    return HypothesisAnnotation(
        finding_id=f.finding_id,
        interpretation=body,
        risk_notes="",
        questions=[],
        evidence_manifest_hash=h,
    )


def deterministic_skeptic(f: CandidateFinding) -> SkepticVerdict:
    if f.witness.constraint_summary.get("approximate_flow"):
        return SkepticVerdict(
            target_finding_id=f.finding_id,
            verdict="DOWNGRADE",
            reason_codes=["SAME_FILE_ORDERING_APPROX"],
            counter_evidence_refs=[],
            promotion_blocked=False,
        )
    if "interprocedural_heuristic" in f.witness.analysis_limits:
        return SkepticVerdict(
            target_finding_id=f.finding_id,
            verdict="DOWNGRADE",
            reason_codes=["INTERPROCEDURAL_HEURISTIC"],
            counter_evidence_refs=[],
            promotion_blocked=False,
        )
    if f.rule_id in ("RULE-SQLI-001", "RULE-XSS-001"):
        if "coarse_taint_approximation" in f.witness.analysis_limits and f.witness.constraint_summary.get(
            "unresolved_calls", 0
        ):
            return SkepticVerdict(
                target_finding_id=f.finding_id,
                verdict="BLOCK_PROMOTION",
                reason_codes=["INTERPROCEDURAL_UNRESOLVED"],
                counter_evidence_refs=[],
                promotion_blocked=True,
            )
        if f.title_template_key.endswith(".graph_flow"):
            return SkepticVerdict(
                target_finding_id=f.finding_id,
                verdict="ALLOW_PROMOTION",
                reason_codes=["GRAPH_DERIVED_FLOW"],
                counter_evidence_refs=[],
                promotion_blocked=False,
            )
        return SkepticVerdict(
            target_finding_id=f.finding_id,
            verdict="DOWNGRADE",
            reason_codes=["LEGACY_COARSE_TEMPLATE"],
            counter_evidence_refs=[],
            promotion_blocked=False,
        )
    return SkepticVerdict(
        target_finding_id=f.finding_id,
        verdict="ALLOW_PROMOTION",
        reason_codes=[],
        counter_evidence_refs=[],
        promotion_blocked=False,
    )
