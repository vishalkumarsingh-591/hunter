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
    if f.rule_id in ("RULE-SQLI-001", "RULE-XSS-001"):
        return SkepticVerdict(
            target_finding_id=f.finding_id,
            verdict="BLOCK_PROMOTION",
            reason_codes=["COARSE_SAME_FILE_ORDERING", "NO_INTERPROCEDURAL_SOUNDNESS"],
            counter_evidence_refs=[],
            promotion_blocked=True,
        )
    return SkepticVerdict(
        target_finding_id=f.finding_id,
        verdict="ALLOW_PROMOTION",
        reason_codes=[],
        counter_evidence_refs=[],
        promotion_blocked=False,
    )
