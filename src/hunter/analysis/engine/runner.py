from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hunter.analysis.rules.evaluators import EVALUATORS
from hunter.analysis.rules.loader import RulePack, load_rule_pack, rule_pack_hash
from hunter.graph.in_memory import InMemoryGraph
from hunter.logging import get_logger
from hunter.models.core import RepoManifest
from hunter.models.findings import CandidateFinding

_LOG = get_logger("hunter.analysis")


@dataclass
class RuleTelemetryRow:
    rule_id: str
    duration_ms: float
    findings_count: int
    status: str


class RuleEngine:
    def __init__(self, pack: RulePack) -> None:
        self.pack = pack
        self.pack_hash = rule_pack_hash(pack)

    def evaluate(
        self, g: InMemoryGraph, manifest: RepoManifest
    ) -> tuple[list[CandidateFinding], list[RuleTelemetryRow]]:
        findings: list[CandidateFinding] = []
        telemetry: list[RuleTelemetryRow] = []
        import time

        for rule in sorted(self.pack.rules, key=lambda r: r.id):
            t0 = time.perf_counter()
            fn = EVALUATORS.get(rule.python_evaluator_id)
            if not fn:
                telemetry.append(
                    RuleTelemetryRow(rule_id=rule.id, duration_ms=0, findings_count=0, status="NO_EVALUATOR")
                )
                continue
            found = fn(g, manifest)
            for f in found:
                if f.rule_id != rule.id:
                    continue
                findings.append(f.model_copy(update={"severity_band_static": rule.severity_band}))  # type: ignore[arg-type]
            dt = (time.perf_counter() - t0) * 1000
            telemetry.append(RuleTelemetryRow(rule_id=rule.id, duration_ms=dt, findings_count=len(found), status="OK"))
            _LOG.info("rule_executed", rule_id=rule.id, findings=len(found), duration_ms=dt)
        # dedupe by finding_id
        by_id = {f.finding_id: f for f in findings}
        return list(by_id.values()), telemetry


def run_analysis(
    g: InMemoryGraph,
    manifest: RepoManifest,
    pack_path: Path | None = None,
) -> tuple[list[CandidateFinding], RulePack, list[RuleTelemetryRow]]:
    path = pack_path or Path(__file__).resolve().parents[1] / "rules" / "packs" / "default.yaml"
    pack = load_rule_pack(path)
    engine = RuleEngine(pack)
    findings, tel = engine.evaluate(g, manifest)
    return findings, pack, tel
