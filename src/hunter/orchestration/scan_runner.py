from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Protocol

from hunter.agents.pipeline import enrich_findings
from hunter.concurrency.pool import resolve_max_inflight, resolve_scan_workers
from hunter.concurrency.resources import detect_system_resources
from hunter.analysis.rules.loader import load_rule_pack, rule_pack_hash
from hunter.graph.security_facts_catalog import catalog_hash
from hunter.models.core import ScanProfile
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
    ScanResources,
    ScanResult,
    ScanStage,
    SnapshotMode,
)
from hunter.observability.metrics import Metrics
from hunter.orchestration.lineage import compute_lineage
from hunter.parse.export import export_ir_artifacts
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
    scan_profile: str,
    catalog_h: str,
) -> str:
    parts = [
        manifest_sha,
        parser_lock,
        schema_version,
        rule_pack_h,
        hunter_build_version(),
        str(agents_disabled),
        llm_model,
        scan_profile,
        catalog_h,
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _packs_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "analysis" / "rules" / "packs"


def _builtin_profile(profile_id: str) -> ScanProfile:
    packs = _packs_dir()
    if profile_id == "generic-php":
        return ScanProfile(
            profile_id="generic-php",
            catalog_ids=["generic-php-v1"],
            adapter_ids=[],
            rule_pack_path=packs / "generic-php.yaml",
        )
    if profile_id in ("wordpress", "full"):
        return ScanProfile(
            profile_id=profile_id,
            catalog_ids=["generic-php-v1", "wordpress-v1"],
            adapter_ids=["wordpress"],
            rule_pack_path=packs / "full.yaml",
        )
    return ScanProfile(
        profile_id="full",
        catalog_ids=["generic-php-v1", "wordpress-v1"],
        adapter_ids=["wordpress"],
        rule_pack_path=packs / "full.yaml",
    )


def _detect_wordpress_signals(repo_root: Path, manifest_files: tuple) -> list[str]:
    signals: list[str] = []
    root = repo_root.resolve()
    path_checks = (
        ("wp-load.php", root / "wp-load.php"),
        ("wp-includes/version.php", root / "wp-includes" / "version.php"),
        ("wp-config-sample.php", root / "wp-config-sample.php"),
    )
    for name, p in path_checks:
        if p.is_file():
            signals.append(f"path:{name}")
    content_markers = (
        "ABSPATH",
        "register_rest_route",
        "Plugin Name:",
        "add_action(",
        "wp_ajax_nopriv_",
        "$wpdb",
    )
    sampled = 0
    for mf in manifest_files:
        if mf.language_guess != "php" or sampled >= 3:
            continue
        path = root / mf.rel_path
        if not path.is_file():
            continue
        try:
            chunk = path.read_text(encoding="utf-8", errors="replace")[:8192]
        except OSError:
            continue
        sampled += 1
        for marker in content_markers:
            if marker in chunk:
                signals.append(f"content:{marker}")
    return signals


def resolve_scan_profile(
    repo_root: Path,
    requested: str,
    manifest_files: tuple,
    *,
    rule_pack_override: Path | None = None,
) -> ScanProfile:
    req = (requested or "auto").strip().lower()
    if req == "auto":
        signals = _detect_wordpress_signals(repo_root, manifest_files)
        profile_id = "full" if len(signals) >= 2 else "generic-php"
        _LOG.info("profile_resolved", requested=req, profile_id=profile_id, detect_signals=signals)
    else:
        profile_id = req if req in ("generic-php", "wordpress", "full") else "full"
    profile = _builtin_profile(profile_id)
    if rule_pack_override is not None:
        profile = profile.model_copy(update={"rule_pack_path": rule_pack_override})
    return profile


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

        resources = detect_system_resources()
        workers = resolve_scan_workers(config.scan_workers, resources=resources)
        max_inflight = resolve_max_inflight(
            config.scan_max_inflight, workers, ram_gb=resources.ram_gb
        )
        scan_resources = ScanResources(
            cpu_count=resources.cpu_count,
            ram_gb=resources.ram_gb,
            workers=workers,
            max_inflight=max_inflight,
        )
        _LOG.info(
            "scan_resources",
            cpu_count=scan_resources.cpu_count,
            ram_gb=scan_resources.ram_gb,
            workers=scan_resources.workers,
            max_inflight=scan_resources.max_inflight,
        )
        quotas = config.quotas
        ingest = run_ingest(root, quotas, workers=workers)
        profile = config.resolved_profile or resolve_scan_profile(
            root,
            config.profile,
            ingest.manifest.files,
            rule_pack_override=config.rule_pack_path,
        )
        config = config.model_copy(update={"resolved_profile": profile})
        cat_h = catalog_hash(profile.catalog_ids)
        snap_mode = SnapshotMode.copy if self.settings.snapshot_mode != "manifest-only" else SnapshotMode.manifest_only
        write_repository_snapshot(out, ingest.manifest, ingest, snap_mode, workers=workers)
        parse_dir = out / "cache" / "parse"
        parseable_files = sum(
            1
            for mf in ingest.manifest.files
            if mf.parse_policy == "parse" and mf.language_guess in ("php", "javascript", "html")
        )
        rule_pack_path = profile.rule_pack_path
        rule_pack = load_rule_pack(rule_pack_path)
        active_adapters = frozenset(profile.adapter_ids)
        if progress:
            fixed_steps = 11  # includes apply_layers (always on)
            optional_steps = 0
            optional_steps += int(config.semantic_ir_v2_enabled or config.resolver_interprocedural_enabled)
            optional_steps += int(
                config.cfg_ssa_enabled and (config.semantic_ir_v2_enabled or config.resolver_interprocedural_enabled)
            )
            optional_steps += int(config.security_popchain_enabled)
            optional_steps += int(config.semantic_diff_enabled or config.incremental_recompute_enabled)
            progress.reset(parseable_files + len(rule_pack.rules) + fixed_steps + optional_steps, f"scan {slug}")
            progress.advance(1, "ingest complete")
            progress.advance(1, "snapshot written")
        parse = parse_manifest(
            ingest.manifest,
            parse_cache_dir=parse_dir,
            max_single_file_bytes=quotas.max_single_file_bytes,
            progress=(lambda step, description=None: progress.advance(step, description) if progress else None),
            structure_complete_mode=self.settings.parse_structure_complete_mode,
            max_ir_nodes_per_file=self.settings.parse_max_ir_nodes_per_file,
            lift_version=self.settings.lift_version,
            workers=workers,
            max_inflight=max_inflight,
        )
        if progress and parseable_files == 0:
            progress.advance(1, "parse complete")
        schema_ver = config.graph_schema_version or self.settings.graph_schema_version
        gbuild = build_graph_from_parse(
            ingest.manifest, parse, schema_ver, run_structural_import=(workers <= 1)
        )
        g = gbuild.graph
        if progress:
            progress.advance(1, "graph built")
        pipe = build_analysis_graph(
            g,
            ingest.manifest,
            parse,
            self.settings,
            profile=profile,
            workers=workers,
            resolver_enabled=config.semantic_ir_v2_enabled or config.resolver_interprocedural_enabled,
            cfg_ssa_enabled=config.cfg_ssa_enabled,
            taint_path_sensitive=config.taint_path_sensitive_enabled,
            security_popchain=config.security_popchain_enabled,
            regex_taint_fallback=self.settings.regex_taint_fallback_enabled,
            structural_stats=gbuild.structural_stats,
        )
        if gbuild.structural_stats:
            st = gbuild.structural_stats
        elif pipe.structural_stats:
            st = pipe.structural_stats
        else:
            st = None
        if st:
            _LOG.info(
                "phase1_structural",
                functions=st.functions,
                methods=st.methods,
                classes=st.classes,
                callsites=st.callsites,
                truncated_files=st.truncated_files,
            )
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
            rule_pack_path,
            pack=rule_pack,
            active_adapters=active_adapters,
            workers=workers,
            progress=(lambda step, description=None: progress.advance(step, description) if progress else None),
        )
        if profile.adapter_ids and profile.adapter_ids[0] == "wordpress":
            from hunter.models.findings import ExposureContext

            updated: list = []
            for f in findings:
                exp = f.exposure_context
                if not exp.framework:
                    exp = exp.model_copy(update={"framework": "wordpress"})
                updated.append(f.model_copy(update={"exposure_context": exp}))
            findings = updated
        rph = rule_pack_hash(pack)
        integrity_ok, issues = check_integrity(g)
        if progress:
            progress.advance(1, "analysis complete")
        sg = out / "semantic_graph"
        g.export_jsonl(sg)
        ir_dir = sg / "ir_exports"
        export_ir_artifacts(parse, ir_dir, workers=workers)
        # Log node type distribution for debugging (nodes use singular "label")
        node_types: dict[str, int] = {}
        for _nid, n in g.nodes.items():
            lab = n.get("label")
            if lab:
                ls = str(lab)
                node_types[ls] = node_types.get(ls, 0) + 1
        _LOG.info("phase2_graph_export", total_nodes=len(g.nodes), node_types=node_types, total_edges=len(g.edges))
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
            profile_id=profile.profile_id,
        )
        if progress:
            progress.advance(1, "confidence")
        det = DeterminismMeta(
            replay_token=_replay_token(
                ingest.manifest.manifest_sha256,
                parse.parser_lock_hash,
                schema_ver,
                rph,
                agents_disabled=not config.agents_enabled,
                llm_model=self.settings.llm_model if config.agents_enabled else "",
                scan_profile=profile.profile_id,
                catalog_h=cat_h,
            ),
            manifest_sha256=ingest.manifest.manifest_sha256,
            parser_lock_hash=parse.parser_lock_hash,
            graph_schema_version=schema_ver,
            rule_pack_hash=rph,
            hunter_version=hunter_build_version(),
            agents_disabled=not config.agents_enabled,
            llm_model_id=self.settings.llm_model if config.agents_enabled else "",
            scan_profile=profile.profile_id,
            catalog_hash=cat_h,
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
            rule_pack=pack,
            scan_profile=profile.profile_id,
            scan_resources=scan_resources,
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


def run_scan(
    plugin_path: Path,
    settings: HunterSettings | None = None,
    progress: ProgressReporter | None = None,
) -> ScanResult:
    s = settings or HunterSettings.load()
    cfg = ScanConfig(
        plugin_root=plugin_path,
        profile=s.scan_profile,
        output_root=s.output_root,
        graph_schema_version=s.graph_schema_version,
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
        scan_workers=s.scan_workers,
        scan_max_inflight=s.scan_max_inflight,
    )
    return ScanRunner(s).run(cfg, progress=progress)
