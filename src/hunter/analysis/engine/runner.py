from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from hunter.analysis.rules.evaluators import EVALUATORS
from hunter.analysis.rules.loader import RulePack, load_rule_pack, rule_pack_hash, schema_meets_minimum
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


@dataclass
class _RuleEvalResult:
    findings: list[CandidateFinding]
    telemetry: RuleTelemetryRow


class RuleEngine:
    def __init__(self, pack: RulePack) -> None:
        self.pack = pack
        self.pack_hash = rule_pack_hash(pack)

    def _evaluate_one_rule(
        self,
        rule,
        g: InMemoryGraph,
        manifest: RepoManifest,
        active_adapters: frozenset[str],
    ) -> _RuleEvalResult:
        import time

        t0 = time.perf_counter()
        if not rule.enabled:
            return _RuleEvalResult(
                [],
                RuleTelemetryRow(rule_id=rule.id, duration_ms=0, findings_count=0, status="RULE_DISABLED"),
            )
        if not schema_meets_minimum(g.schema_version, rule.min_graph_schema_version):
            return _RuleEvalResult(
                [],
                RuleTelemetryRow(rule_id=rule.id, duration_ms=0, findings_count=0, status="RULE_SKIPPED_SCHEMA"),
            )
        if rule.requires_adapter:
            if rule.requires_adapter not in active_adapters:
                return _RuleEvalResult(
                    [],
                    RuleTelemetryRow(
                        rule_id=rule.id, duration_ms=0, findings_count=0, status="RULE_SKIPPED_ADAPTER"
                    ),
                )
        fn = EVALUATORS.get(rule.python_evaluator_id)
        if not fn:
            return _RuleEvalResult(
                [],
                RuleTelemetryRow(rule_id=rule.id, duration_ms=0, findings_count=0, status="NO_EVALUATOR"),
            )
        found = fn(g, manifest)
        findings: list[CandidateFinding] = []
        for f in found:
            if f.rule_id != rule.id:
                continue
            findings.append(f.model_copy(update={"severity_band_static": rule.severity_band}))  # type: ignore[arg-type]
        dt = (time.perf_counter() - t0) * 1000
        return _RuleEvalResult(
            findings,
            RuleTelemetryRow(rule_id=rule.id, duration_ms=dt, findings_count=len(findings), status="OK"),
        )

    def evaluate(
        self,
        g: InMemoryGraph,
        manifest: RepoManifest,
        *,
        active_adapters: frozenset[str] | None = None,
        workers: int = 1,
        progress: Callable[[int, str | None], None] | None = None,
    ) -> tuple[list[CandidateFinding], list[RuleTelemetryRow]]:
        adapters = active_adapters or frozenset()
        rules = sorted(self.pack.rules, key=lambda r: r.id)
        findings: list[CandidateFinding] = []
        telemetry: list[RuleTelemetryRow] = []

        if workers <= 1 or len(rules) <= 1:
            for rule in rules:
                res = self._evaluate_one_rule(rule, g, manifest, adapters)
                findings.extend(res.findings)
                telemetry.append(res.telemetry)
                if res.telemetry.status == "OK":
                    _LOG.info(
                        "rule_executed",
                        rule_id=rule.id,
                        findings=res.telemetry.findings_count,
                        duration_ms=res.telemetry.duration_ms,
                    )
                if progress:
                    progress(1, f"rule {rule.id}")
        else:
            results: dict[str, _RuleEvalResult] = {}
            with ThreadPoolExecutor(max_workers=min(workers, len(rules))) as pool:
                futures = {
                    pool.submit(self._evaluate_one_rule, rule, g, manifest, adapters): rule for rule in rules
                }
                for future in as_completed(futures):
                    rule = futures[future]
                    results[rule.id] = future.result()
            for rule in rules:
                res = results[rule.id]
                findings.extend(res.findings)
                telemetry.append(res.telemetry)
                if res.telemetry.status == "OK":
                    _LOG.info(
                        "rule_executed",
                        rule_id=rule.id,
                        findings=res.telemetry.findings_count,
                        duration_ms=res.telemetry.duration_ms,
                    )
                if progress:
                    progress(1, f"rule {rule.id}")

        by_id = {f.finding_id: f for f in findings}
        return list(by_id.values()), telemetry


def run_analysis(
    g: InMemoryGraph,
    manifest: RepoManifest,
    pack_path: Path | None = None,
    *,
    pack: RulePack | None = None,
    active_adapters: frozenset[str] | None = None,
    workers: int = 1,
    progress: Callable[[int, str | None], None] | None = None,
) -> tuple[list[CandidateFinding], RulePack, list[RuleTelemetryRow]]:
    if pack is None:
        path = pack_path or Path(__file__).resolve().parents[1] / "rules" / "packs" / "default.yaml"
        pack = load_rule_pack(path)
    engine = RuleEngine(pack)
    findings, tel = engine.evaluate(
        g, manifest, active_adapters=active_adapters, workers=workers, progress=progress
    )
    return findings, pack, tel
