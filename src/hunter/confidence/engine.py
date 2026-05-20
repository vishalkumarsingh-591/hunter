from __future__ import annotations

from pathlib import Path

import yaml

from hunter.models.findings import (
    CandidateFinding,
    ConfidenceExplanation,
    ConfidenceRecord,
    SkepticVerdict,
    StaticVerificationResult,
)


def _bucket(score: float, th: dict[str, float]) -> str:
    if score >= th["VERY_HIGH"]:
        return "VERY_HIGH"
    if score >= th["HIGH"]:
        return "HIGH"
    if score >= th["MEDIUM"]:
        return "MEDIUM"
    if score >= th["LOW"]:
        return "LOW"
    return "VERY_LOW"


class ConfidenceEngine:
    def __init__(self, weights_path: Path | None = None, profile_id: str = "") -> None:
        path = weights_path or Path(__file__).with_name("weights.yaml")
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        self.weights: dict[str, float] = {str(k): float(v) for k, v in raw.get("weights", {}).items()}
        self.thresholds: dict[str, float] = {str(k): float(v) for k, v in raw.get("thresholds", {}).items()}
        profiles = raw.get("profiles") or {}
        if profile_id and profile_id in profiles:
            overrides = profiles[profile_id].get("weights") or {}
            for k, v in overrides.items():
                self.weights[str(k)] = float(v)

    def build_features(
        self,
        f: CandidateFinding,
        verification: StaticVerificationResult,
        skeptic: SkepticVerdict | None,
        graph_integrity_ok: bool,
    ) -> dict[str, float | bool]:
        witness_len = float(len(f.witness.summary_hops))
        semantic_trace_len = float(len(f.witness.semantic_trace))
        constraint_strength = float(f.witness.constraint_summary.get("constraint_strength", 0.0) or 0.0)
        has_limits = bool(f.witness.analysis_limits)
        sql_prepare = bool(f.witness.constraint_summary.get("sql_prepare_on_path"))
        graph_derived = bool(f.witness.semantic_trace) and any(t.startswith("graph:") for t in f.witness.semantic_trace)
        approximate_flow = bool(f.witness.constraint_summary.get("approximate_flow"))
        lift_derived = "lift_derived_flow" in f.witness.semantic_trace
        return {
            "witness_shortest_len": witness_len,
            "semantic_trace_len": semantic_trace_len,
            "constraint_strength": constraint_strength / 100.0 if constraint_strength > 1 else constraint_strength,
            "sanitizer_on_all_paths": sql_prepare,
            "dynamic_call_unresolved_on_path": int(f.witness.constraint_summary.get("unresolved_calls", 0) or 0) > 0,
            "analysis_limits_present": has_limits,
            "graph_derived_witness": graph_derived,
            "missing_guard_signal": "MISSING_GUARD" in " ".join(f.witness.semantic_trace)
            or f.rule_id.startswith("RULE-WP-REST"),
            "ajax_nopriv_true": f.wp_context.ajax_nopriv,
            "skeptic_block_promotion": bool(skeptic and skeptic.promotion_blocked),
            "static_verifier_refuted": verification.status == "REFUTED",
            "graph_integrity_ok": graph_integrity_ok,
            "approximate_flow": approximate_flow,
            "lift_derived_flow": lift_derived,
            "graph_integrity_failed": not graph_integrity_ok,
        }

    def score(
        self,
        f: CandidateFinding,
        verification: StaticVerificationResult,
        skeptic: SkepticVerdict | None,
        graph_integrity_ok: bool,
    ) -> ConfidenceRecord:
        feats = self.build_features(f, verification, skeptic, graph_integrity_ok)
        score = 0.45
        explanations: list[ConfidenceExplanation] = []
        for k, v in feats.items():
            w = self.weights.get(k)
            if w is None:
                continue
            if isinstance(v, bool):
                contrib = w * (1.0 if v else 0.0)
            else:
                contrib = w * float(v)
            score += contrib
            explanations.append(ConfidenceExplanation(feature=k, contribution=contrib, note=""))
        score = max(0.0, min(1.0, score))
        bucket = _bucket(score, self.thresholds)
        return ConfidenceRecord(
            finding_id=f.finding_id,
            score=score,
            bucket=bucket,  # type: ignore[arg-type]
            features=feats,
            explanations=explanations,
        )


def score_finding(
    f: CandidateFinding,
    verification: StaticVerificationResult,
    skeptic: SkepticVerdict | None,
    graph_integrity_ok: bool,
    weights_path: Path | None = None,
    profile_id: str = "",
) -> ConfidenceRecord:
    return ConfidenceEngine(weights_path, profile_id=profile_id).score(f, verification, skeptic, graph_integrity_ok)
