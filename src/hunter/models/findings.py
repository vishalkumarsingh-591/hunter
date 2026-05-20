from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class WitnessHop(BaseModel):
    from_id: str
    to_id: str
    edge_kind: str


class Witness(BaseModel):
    path_edges: list[str] = Field(default_factory=list)
    summary_hops: list[WitnessHop] = Field(default_factory=list)
    taint_labels: list[str] = Field(default_factory=list)
    semantic_trace: list[str] = Field(default_factory=list)
    constraint_summary: dict[str, int | float | bool | str] = Field(default_factory=dict)
    analysis_limits: list[str] = Field(default_factory=list)


class ExposureContext(BaseModel):
    surface: Literal["HTTP_PUBLIC", "HTTP_AUTH", "ADMIN", "CLI", "CRON", "UNKNOWN"] = "UNKNOWN"
    framework: str = ""


class WPContextFeatures(BaseModel):
    ajax_nopriv: bool = False
    rest_route_public: bool = False
    exposure: Literal["PUBLIC_AUTHENTICATED", "ADMIN_ONLY", "AJAX_NOPRIV", "UNKNOWN"] = "UNKNOWN"
    capability_literal_present: bool = False
    nonce_guard_approx: bool = False


class LocationAnchor(BaseModel):
    file_rel_path: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    start_byte: int
    end_byte: int
    ir_node_id: str
    neo4j_node_id: str | None = None


class CandidateFinding(BaseModel):
    finding_id: str
    rule_id: str
    severity_band_static: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    title_template_key: str
    anchors: list[LocationAnchor] = Field(default_factory=list)
    witness: Witness = Field(default_factory=Witness)
    exposure_context: ExposureContext = Field(default_factory=ExposureContext)
    wp_context: WPContextFeatures = Field(default_factory=WPContextFeatures)
    determinism_meta_ref: str = ""  # points to scan-level DeterminismMeta.replay_token fragment


class VerificationCheck(BaseModel):
    check_id: str
    passed: bool | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class StaticVerificationResult(BaseModel):
    status: Literal["CONFIRMED", "REFUTED", "INCONCLUSIVE"]
    checks: list[VerificationCheck] = Field(default_factory=list)
    artifact_sha256: str = ""


class HypothesisAnnotation(BaseModel):
    finding_id: str
    interpretation: str = ""
    risk_notes: str = ""
    questions: list[str] = Field(default_factory=list)
    evidence_manifest_hash: str = ""


class SkepticVerdict(BaseModel):
    target_finding_id: str
    verdict: Literal["ALLOW_PROMOTION", "BLOCK_PROMOTION", "DOWNGRADE"]
    reason_codes: list[str] = Field(default_factory=list)
    counter_evidence_refs: list[str] = Field(default_factory=list)
    promotion_blocked: bool = False


class ConfidenceExplanation(BaseModel):
    feature: str
    contribution: float
    note: str = ""


class ConfidenceRecord(BaseModel):
    finding_id: str
    score: float
    bucket: Literal["VERY_LOW", "LOW", "MEDIUM", "HIGH", "VERY_HIGH"]
    features: dict[str, float | bool] = Field(default_factory=dict)
    explanations: list[ConfidenceExplanation] = Field(default_factory=list)


class EnrichedFinding(BaseModel):
    candidate: CandidateFinding
    hypothesis: HypothesisAnnotation | None = None
    skeptic: SkepticVerdict | None = None
    verification: StaticVerificationResult
    confidence: ConfidenceRecord
