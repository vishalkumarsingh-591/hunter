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
    def __init__(self, weights_path: Path | None = None) -> None:
        path = weights_path or Path(__file__).with_name("weights.yaml")
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        self.weights: dict[str, float] = {str(k): float(v) for k, v in raw["weights"].items()}
        self.thresholds: dict[str, float] = {str(k): float(v) for k, v in raw["thresholds"].items()}

    def build_features(
        self,
        f: CandidateFinding,
        verification: StaticVerificationResult,
        skeptic: SkepticVerdict | None,
        graph_integrity_ok: bool,
    ) -> dict[str, float | bool]:
        witness_len = float(len(f.witness.summary_hops))
        return {
            "witness_shortest_len": witness_len,
            "sanitizer_on_all_paths": False,
            "dynamic_call_unresolved_on_path": "approx" in " ".join(f.witness.path_edges),
            "ajax_nopriv_true": f.wp_context.ajax_nopriv,
            "skeptic_block_promotion": bool(skeptic and skeptic.promotion_blocked),
            "static_verifier_refuted": verification.status == "REFUTED",
            "graph_integrity_ok": graph_integrity_ok,
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
) -> ConfidenceRecord:
    return ConfidenceEngine(weights_path).score(f, verification, skeptic, graph_integrity_ok)
