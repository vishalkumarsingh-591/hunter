from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Protocol

from hunter.agents.pipeline import enrich_findings
from hunter.analysis.rules.loader import load_rule_pack, rule_pack_hash
from hunter.analysis.engine.runner import run_analysis
from hunter.graph.builder import build_graph_from_parse
from hunter.graph.build_pipeline import build_analysis_graph
from hunter.graph.integrity import check_integrity
from hunter.graph.neo4j_client import try_bulk_write_graph, try_write_schema_meta
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
from hunter.orchestration.lineage import compute_lineage
from hunter.orchestration.scan_status import write_scan_status
from hunter.parse.run import parse_manifest
from hunter.persistence.database import ScanRow, init_db, session_scope
from hunter.persistence.repositories import AuditRepository, ScanRepository
from hunter.reporting.renderer import write_scan_outputs
from hunter.settings import HunterSettings, hunter_build_version
_LOG = get_logger("hunter.scan")


class ProgressReporter(Protocol):
    def reset(self, total: int, description: str | None = None) -> None: ...

    def advance(self, step: int = 1, description: str | None = None) -> None: ...

    def close(self) -> None: ...


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

    def run(self, config: ScanConfig, progress: ProgressReporter | None = None) -> ScanResult:
        scan_id = config.scan_id or uuid.uuid4().hex
        trace_id = config.trace_id or scan_id
        set_scan_context(scan_id=scan_id, trace_id=trace_id)
        root = config.plugin_root.resolve()
        slug = _slug(root)
        # Isolate each scan so re-uploading the same plugin slug does not overwrite prior results.
        out = (config.output_root / slug / scan_id).resolve()
        out.mkdir(parents=True, exist_ok=True)
        shared_cache = self.settings.parse_cache_root
        shared_cache.mkdir(parents=True, exist_ok=True)

        def _status(stage: str, detail: str = "", pct: float | None = None) -> None:
            write_scan_status(
                out,
                scan_id=scan_id,
                status="RUNNING",
                stage=stage,
                detail=detail,
                progress_pct=pct,
            )

        try:
            return self._run_pipeline(
                config=config,
                scan_id=scan_id,
                trace_id=trace_id,
                root=root,
                slug=slug,
                out=out,
                parse_cache_dir=shared_cache,
                progress=progress,
                status_cb=_status,
            )
        except Exception as exc:  # noqa: BLE001
            write_scan_status(
                out,
                scan_id=scan_id,
                status="FAILED",
                stage="failed",
                detail=str(exc),
                error=str(exc),
            )
            if self.settings.database_url:
                try:
                    with session_scope() as s:
                        ScanRepository(s).mark_failed(scan_id, str(exc))
                except Exception:  # noqa: BLE001
                    pass
            raise

    def _run_pipeline(
        self,
        *,
        config: ScanConfig,
        scan_id: str,
        trace_id: str,
        root: Path,
        slug: str,
        out: Path,
        parse_cache_dir: Path,
        progress: ProgressReporter | None,
        status_cb,
    ) -> ScanResult:
        self.metrics.inc("scans_started")
        _LOG.info("scan_started", scan_id=scan_id, plugin=str(root))
        status_cb("ingest", "Reading plugin files…", 5)
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
                            source_type=config.dashboard_meta.get("source_type", "local"),
                            source_label=config.dashboard_meta.get("source_label"),
                        )
                    )
                    AuditRepository(s).append("scan_started", scan_id, {"plugin": str(root)})
            except Exception as exc:  # noqa: BLE001
                _LOG.warning("persistence_skipped", error=str(exc))

        quotas = config.quotas
        ingest = run_ingest(root, quotas)
        status_cb("snapshot", "Saving repository snapshot…", 10)
        snap_mode = (
            SnapshotMode.copy if self.settings.snapshot_mode != "manifest-only" else SnapshotMode.manifest_only
        )
        write_repository_snapshot(out, ingest.manifest, ingest, snap_mode)
        parseable_files = sum(
            1
            for mf in ingest.manifest.files
            if mf.parse_policy == "parse" and mf.language_guess in ("php", "javascript", "html")
        )
        if parseable_files == 0:
            raise RuntimeError(
                "Scan did not find any parseable PHP/JS/HTML files in the source. "
                "Check that the upload contains a real WordPress plugin/theme."
            )
        rule_pack_path = config.rule_pack_path or Path(__file__).resolve().parents[1] / "analysis" / "rules" / "packs" / "default.yaml"
        rule_pack = load_rule_pack(rule_pack_path)
        if progress:
            fixed_steps = 11  # includes apply_layers (always on)
            optional_steps = 0
            optional_steps += int(config.semantic_ir_v2_enabled or config.resolver_interprocedural_enabled)
            optional_steps += int(config.cfg_ssa_enabled and (config.semantic_ir_v2_enabled or config.resolver_interprocedural_enabled))
            optional_steps += int(config.security_popchain_enabled)
            optional_steps += int(config.semantic_diff_enabled or config.incremental_recompute_enabled)
            progress.reset(parseable_files + len(rule_pack.rules) + fixed_steps + optional_steps, f"scan {slug}")
            progress.advance(1, "ingest complete")
            progress.advance(1, "snapshot written")
        status_cb("parse", f"Parsing {parseable_files} files…", 20)

        def _parse_progress(step: int, description: str | None = None) -> None:
            if progress:
                progress.advance(step, description)
            if description and parseable_files:
                # rough parse progress 20–55%
                done = min(parseable_files, getattr(_parse_progress, "_n", 0) + step)  # type: ignore[attr-defined]
                _parse_progress._n = done  # type: ignore[attr-defined]
                pct = 20 + (35 * done / max(parseable_files, 1))
                status_cb("parse", description, pct)

        _parse_progress._n = 0  # type: ignore[attr-defined]
        parse = parse_manifest(
            ingest.manifest,
            parse_cache_dir=parse_cache_dir,
            max_single_file_bytes=quotas.max_single_file_bytes,
            progress=_parse_progress,
            structure_complete_mode=self.settings.parse_structure_complete_mode,
            max_ir_nodes_per_file=self.settings.parse_max_ir_nodes_per_file,
            lift_version=self.settings.lift_version,
        )
        if progress and parseable_files == 0:
            progress.advance(1, "parse complete")
        status_cb("graph", "Building security graph…", 55)
        gbuild = build_graph_from_parse(ingest.manifest, parse, self.settings.graph_schema_version)
        g = gbuild.graph
        if progress:
            progress.advance(1, "graph built")
        pipe = build_analysis_graph(
            g,
            ingest.manifest,
            parse,
            self.settings,
            wp_semantics_v2=config.wp_semantics_v2_enabled,
            resolver_enabled=config.semantic_ir_v2_enabled or config.resolver_interprocedural_enabled,
            cfg_ssa_enabled=config.cfg_ssa_enabled,
            taint_path_sensitive=config.taint_path_sensitive_enabled,
            security_popchain=config.security_popchain_enabled,
            regex_taint_fallback=self.settings.regex_taint_fallback_enabled,
            structural_stats=gbuild.structural_stats,
        )
        if gbuild.structural_stats:
            st = gbuild.structural_stats
            _LOG.info(
                "phase1_structural",
                functions=st.functions,
                methods=st.methods,
                classes=st.classes,
                callsites=st.callsites,
                truncated_files=st.truncated_files,
            )
        status_cb("analysis", "Running security rules…", 75)
        if progress:
            progress.advance(1, "wp semantics")
            progress.advance(1, "taint")
            if config.security_popchain_enabled:
                progress.advance(1, "security advanced")
            progress.advance(1, "layers applied")
        _LOG.info(
            "graph_pipeline_complete",
            wp_hooks=pipe.wp_hooks,
            security_signals=pipe.security_signals,
            interprocedural_edges=pipe.interprocedural_edges,
        )
        findings, pack, _tel = run_analysis(
            g,
            ingest.manifest,
            config.rule_pack_path,
            pack=rule_pack,
            progress=(lambda step, description=None: progress.advance(step, description) if progress else None),
        )
        rph = rule_pack_hash(pack)
        integrity_ok, issues = check_integrity(g)
        if progress:
            progress.advance(1, "analysis complete")
        sg = out / "semantic_graph"
        g.export_jsonl(sg)
        ir_dir = sg / "ir_exports"
        ir_dir.mkdir(parents=True, exist_ok=True)
        # Log node type distribution for debugging (nodes use singular "label")
        node_types: dict[str, int] = {}
        for _nid, n in g.nodes.items():
            lab = n.get("label")
            if lab:
                ls = str(lab)
                node_types[ls] = node_types.get(ls, 0) + 1
        _LOG.info("phase2_graph_export", total_nodes=len(g.nodes), node_types=node_types, total_edges=len(g.edges))
        for rel, art in parse.per_file.items():
            safe = rel.replace("\\", "_").replace("/", "__")
            (ir_dir / f"{safe}.json").write_text(art.model_dump_json(), encoding="utf-8")
        if config.semantic_diff_enabled or config.incremental_recompute_enabled:
            lineage = compute_lineage(out, ingest.manifest)
            self.metrics.inc("semantic_diff_added_files", len(lineage.semantic_diff.added_files))
            self.metrics.inc("semantic_diff_changed_files", len(lineage.semantic_diff.changed_files))
            if progress:
                progress.advance(1, "semantic diff")
        try_write_schema_meta(
            self.settings.neo4j_uri,
            self.settings.neo4j_user,
            self.settings.neo4j_password,
            g.snapshot_id,
            self.settings.graph_schema_version,
        )
        if config.neo4j_layered_write_enabled:
            try_bulk_write_graph(
                self.settings.neo4j_uri,
                self.settings.neo4j_user,
                self.settings.neo4j_password,
                g,
                batch_size=self.settings.graph_batch_size,
            )
        if progress:
            progress.advance(1, "schema meta")
        enriched, trace = enrich_findings(
            findings,
            scan_id=scan_id,
            graph_integrity_ok=integrity_ok,
            agents_enabled=config.agents_enabled,
            confidence_weights=self.settings.confidence_weights_path,
        )
        status_cb("reporting", "Writing report…", 90)
        if progress:
            progress.advance(1, "confidence")
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
            settings=self.settings,
        )
        if progress:
            progress.advance(1, "reporting")
            progress.close()
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
                    ScanRepository(s).finish_scan(
                        scan_id,
                        "COMPLETED",
                        g.snapshot_id,
                        det.replay_token,
                        output_dir=str(out),
                        findings_count=len(enriched),
                    )
                    AuditRepository(s).append(
                        "report_emitted",
                        scan_id,
                        {"output_dir": str(out), "findings": len(enriched)},
                    )
            except Exception as exc:  # noqa: BLE001
                _LOG.warning("persistence_finish_skipped", error=str(exc))
            if enriched and config.persist_findings_to_db:
                try:
                    payloads = [e.candidate.model_dump() for e in enriched]
                    batch = 200
                    for i in range(0, len(payloads), batch):
                        with session_scope() as s:
                            ScanRepository(s).insert_findings(scan_id, payloads[i : i + batch])
                except Exception as exc:  # noqa: BLE001
                    _LOG.warning("persistence_findings_skipped", error=str(exc), count=len(enriched))
        write_scan_status(
            out,
            scan_id=scan_id,
            status="COMPLETED",
            stage="complete",
            detail=f"{len(enriched)} findings",
            progress_pct=100,
        )
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


def run_scan(
    plugin_path: Path,
    settings: HunterSettings | None = None,
    progress: ProgressReporter | None = None,
) -> ScanResult:
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
        semantic_ir_v2_enabled=s.semantic_ir_v2_enabled,
        resolver_interprocedural_enabled=s.resolver_interprocedural_enabled,
        cfg_ssa_enabled=s.cfg_ssa_enabled,
        taint_path_sensitive_enabled=s.taint_path_sensitive_enabled,
        wp_semantics_v2_enabled=s.wp_semantics_v2_enabled,
        security_popchain_enabled=s.security_popchain_enabled,
        semantic_diff_enabled=s.semantic_diff_enabled,
        incremental_recompute_enabled=s.incremental_recompute_enabled,
        neo4j_layered_write_enabled=s.neo4j_layered_write_enabled,
    )
    return ScanRunner(s).run(cfg, progress=progress)
