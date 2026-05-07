from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from hunter.agents.pipeline import enrich_findings
from hunter.analysis.engine.runner import run_analysis
from hunter.analysis.rules.loader import rule_pack_hash
from hunter.analysis.taint.simple import augment_taint
from hunter.graph.builder import build_graph_from_parse
from hunter.graph.integrity import check_integrity
from hunter.graph.neo4j_client import try_write_schema_meta
from hunter.ingest.snapshot_writer import write_repository_snapshot
from hunter.ingest.walk import run_ingest
from hunter.logging import get_logger, set_scan_context
from hunter.models.core import (
    DeterminismMeta,
    QuotaConfig,
    ScanConfig,
    ScanResult,
    ScanStage,
    SnapshotMode,
)
from hunter.observability.metrics import Metrics
from hunter.parse.run import parse_manifest
from hunter.persistence.database import ScanRow, init_db, session_scope
from hunter.persistence.repositories import AuditRepository, ScanRepository
from hunter.reporting.renderer import write_scan_outputs
from hunter.settings import HunterSettings, hunter_build_version
from hunter.wp.augment import augment_wordpress_semantics

_LOG = get_logger("hunter.scan")


def _slug(root: Path) -> str:
    name = root.resolve().name or "plugin"
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    return safe[:200] or "plugin"


def _replay_token(
    manifest_sha: str,
    parser_lock: str,
    schema_version: str,
    rule_pack_h: str,
    agents_disabled: bool,
    llm_model: str,
) -> str:
    parts = [
        manifest_sha,
        parser_lock,
        schema_version,
        rule_pack_h,
        hunter_build_version(),
        str(agents_disabled),
        llm_model,
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


class ScanRunner:
    def __init__(self, settings: HunterSettings) -> None:
        self.settings = settings
        self.metrics = Metrics()
        init_db(settings.database_url)

    def run(self, config: ScanConfig) -> ScanResult:
        scan_id = config.scan_id or uuid.uuid4().hex
        trace_id = config.trace_id or scan_id
        set_scan_context(scan_id=scan_id, trace_id=trace_id)
        root = config.plugin_root.resolve()
        slug = _slug(root)
        out = (config.output_root / slug).resolve()
        out.mkdir(parents=True, exist_ok=True)
        self.metrics.inc("scans_started")
        _LOG.info("scan_started", scan_id=scan_id, plugin=str(root))
        if self.settings.database_url:
            try:
                with session_scope() as s:
                    h = hashlib.sha256(str(root).encode()).hexdigest()[:32]
                    ScanRepository(s).upsert_scan_start(
                        ScanRow(
                            id=scan_id,
                            plugin_slug=slug,
                            root_path_hash=h,
                            status="RUNNING",
                        )
                    )
                    AuditRepository(s).append("scan_started", scan_id, {"plugin": str(root)})
            except Exception as exc:  # noqa: BLE001
                _LOG.warning("persistence_skipped", error=str(exc))

        quotas = config.quotas
        ingest = run_ingest(root, quotas)
        snap_mode = (
            SnapshotMode.copy if self.settings.snapshot_mode != "manifest-only" else SnapshotMode.manifest_only
        )
        write_repository_snapshot(out, ingest.manifest, ingest, snap_mode)
        parse_dir = out / "cache" / "parse"
        parse = parse_manifest(
            ingest.manifest,
            parse_cache_dir=parse_dir,
            max_single_file_bytes=quotas.max_single_file_bytes,
        )
        gbuild = build_graph_from_parse(ingest.manifest, parse, self.settings.graph_schema_version)
        g = gbuild.graph
        augment_wordpress_semantics(g, ingest.manifest)
        augment_taint(g, ingest.manifest)
        findings, pack, _tel = run_analysis(g, ingest.manifest, config.rule_pack_path)
        rph = rule_pack_hash(pack)
        integrity_ok, issues = check_integrity(g)
        sg = out / "semantic_graph"
        g.export_jsonl(sg)
        ir_dir = sg / "ir_exports"
        ir_dir.mkdir(parents=True, exist_ok=True)
        for rel, art in parse.per_file.items():
            safe = rel.replace("\\", "_").replace("/", "__")
            (ir_dir / f"{safe}.json").write_text(art.model_dump_json(), encoding="utf-8")
        try_write_schema_meta(
            self.settings.neo4j_uri,
            self.settings.neo4j_user,
            self.settings.neo4j_password,
            g.snapshot_id,
            self.settings.graph_schema_version,
        )
        enriched, trace = enrich_findings(
            findings,
            scan_id=scan_id,
            graph_integrity_ok=integrity_ok,
            agents_enabled=config.agents_enabled,
            confidence_weights=self.settings.confidence_weights_path,
        )
        det = DeterminismMeta(
            replay_token=_replay_token(
                ingest.manifest.manifest_sha256,
                parse.parser_lock_hash,
                self.settings.graph_schema_version,
                rph,
                agents_disabled=not config.agents_enabled,
                llm_model=self.settings.llm_model if config.agents_enabled else "",
            ),
            manifest_sha256=ingest.manifest.manifest_sha256,
            parser_lock_hash=parse.parser_lock_hash,
            graph_schema_version=self.settings.graph_schema_version,
            rule_pack_hash=rph,
            hunter_version=hunter_build_version(),
            agents_disabled=not config.agents_enabled,
            llm_model_id=self.settings.llm_model if config.agents_enabled else "",
        )
        write_scan_outputs(
            out,
            scan_id=scan_id,
            manifest=ingest.manifest,
            ingest=ingest,
            parse=parse,
            snapshot_id=g.snapshot_id,
            determinism=det,
            enriched=enriched,
            reasoning_trace=trace,
            graph_integrity_ok=integrity_ok,
        )
        log_path = out / "logs" / f"scan-{scan_id}.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        summary = {
            "event": "scan_summary",
            "scan_id": scan_id,
            "findings": len(enriched),
            "snapshot_id": g.snapshot_id,
            "graph_integrity_ok": integrity_ok,
            "metrics": self.metrics.snapshot(),
        }
        log_path.write_text(json.dumps(summary) + "\n", encoding="utf-8")
        if self.settings.database_url:
            try:
                with session_scope() as s:
                    sr = ScanRepository(s)
                    sr.finish_scan(scan_id, "COMPLETED", g.snapshot_id, det.replay_token)
                    sr.insert_findings(scan_id, [e.candidate.model_dump() for e in enriched])
                    AuditRepository(s).append(
                        "report_emitted",
                        scan_id,
                        {"output_dir": str(out), "findings": len(enriched)},
                    )
            except Exception as exc:  # noqa: BLE001
                _LOG.warning("persistence_finish_skipped", error=str(exc))
        self.metrics.inc("scans_completed")
        _LOG.info("scan_completed", scan_id=scan_id, findings=len(enriched))
        return ScanResult(
            scan_id=scan_id,
            plugin_slug=slug,
            output_dir=out,
            snapshot_id=g.snapshot_id,
            stages_completed=[
                ScanStage.ingest,
                ScanStage.parse,
                ScanStage.graph,
                ScanStage.wp_semantics,
                ScanStage.taint,
                ScanStage.analysis,
                ScanStage.verify_static,
                ScanStage.agents,
                ScanStage.confidence,
                ScanStage.reporting,
            ],
            ingest=ingest,
            determinism=det,
            graph_integrity_ok=integrity_ok,
            errors=[f"graph_integrity: {i}" for i in issues] if not integrity_ok else [],
        )


def run_scan(plugin_path: Path, settings: HunterSettings | None = None) -> ScanResult:
    s = settings or HunterSettings.load()
    cfg = ScanConfig(
        plugin_root=plugin_path,
        output_root=s.output_root,
        quotas=QuotaConfig(
            max_files=s.ingest_max_files,
            max_total_bytes=s.ingest_max_total_bytes,
            max_single_file_bytes=s.ingest_max_single_file_bytes,
            max_depth=s.ingest_max_depth,
            follow_symlinks=s.ingest_follow_symlinks,
        ),
        agents_enabled=s.agents_enabled,
        neo4j_uri=s.neo4j_uri,
        neo4j_user=s.neo4j_user,
        neo4j_password=s.neo4j_password,
        database_url=s.database_url,
        rule_pack_path=s.rule_pack_path,
        graph_schema_version=s.graph_schema_version,
        rule_timeout_seconds=s.rule_timeout_seconds,
    )
    return ScanRunner(s).run(cfg)
