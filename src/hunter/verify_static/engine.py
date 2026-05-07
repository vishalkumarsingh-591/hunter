from __future__ import annotations

import hashlib
import json

from hunter.models.findings import CandidateFinding, StaticVerificationResult, VerificationCheck


def verify_finding(f: CandidateFinding) -> StaticVerificationResult:
    """Non-LLM static verification: structural checks on witness and rule family."""
    checks: list[VerificationCheck] = []
    witness_edges = len(f.witness.path_edges)
    checks.append(
        VerificationCheck(
            check_id="HAS_WITNESS_PATH",
            passed=witness_edges > 0 or f.rule_id == "RULE-WP-AJAX-001",
            details={"edges": witness_edges},
        )
    )
    checks.append(
        VerificationCheck(
            check_id="ANCHOR_LINE_POSITIVE",
            passed=all(a.start_line > 0 for a in f.anchors),
            details={"anchors": len(f.anchors)},
        )
    )
    if f.rule_id == "RULE-WP-AJAX-001":
        checks.append(
            VerificationCheck(
                check_id="AJAX_NOPRIV_FLAG",
                passed=f.wp_context.ajax_nopriv is True,
                details={},
            )
        )
    refuted = any(c.passed is False for c in checks)
    inconclusive = any(c.passed is None for c in checks)
    status = "REFUTED" if refuted else ("INCONCLUSIVE" if inconclusive else "CONFIRMED")
    payload = json.dumps([c.model_dump() for c in checks], sort_keys=True).encode()
    return StaticVerificationResult(
        status=status,  # type: ignore[arg-type]
        checks=checks,
        artifact_sha256=hashlib.sha256(payload).hexdigest(),
    )
