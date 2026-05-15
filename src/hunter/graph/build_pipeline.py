"""Single facade for graph mutation during scans."""

from __future__ import annotations

from dataclasses import dataclass, field

from hunter.analysis.semantic.cfg import build_cfg
from hunter.analysis.semantic.resolver import ResolutionResult
from hunter.analysis.semantic.resolver_graph import build_resolution_from_graph
from hunter.analysis.semantic.ssa import build_ssa
from hunter.analysis.taint.interprocedural import augment_taint_interprocedural
from hunter.analysis.taint.simple import augment_taint
from hunter.graph.in_memory import InMemoryGraph
from hunter.graph.layers import apply_layers
from hunter.graph.security_advanced_graph import augment_security_from_graph
from hunter.graph.security_facts_catalog import SecurityFactsStats, augment_security_facts
from hunter.graph.structural_import import StructuralImportStats
from hunter.graph.wp_import import import_wordpress_semantics
from hunter.models.core import RepoManifest
from hunter.models.ir import ParseRunResult
from hunter.settings import HunterSettings


@dataclass
class GraphBuildPipelineResult:
    structural_stats: StructuralImportStats | None = None
    security_stats: SecurityFactsStats | None = None
    resolution: ResolutionResult | None = None
    wp_hooks: int = 0
    security_signals: int = 0
    interprocedural_edges: int = 0
    layer_counts: dict[str, int] = field(default_factory=dict)


def _export_resolution(g: InMemoryGraph, resolution: ResolutionResult) -> None:
    for node in resolution.nodes:
        rid = f"resnode:{g.snapshot_id}:{node.file_rel_path}:{node.function_name}:{node.line}"
        g.upsert_node(
            rid,
            "ResolutionNode",
            {"name": node.function_name, "file": node.file_rel_path, "line": node.line},
        )
        g.add_edge(f"file:{g.snapshot_id}:{node.file_rel_path}", "HAS_SYMBOL_RESOLUTION", rid, {})
    for edge in resolution.edges:
        sid = f"resnode:{g.snapshot_id}:{edge.file_rel_path}:{edge.caller}:{edge.line}"
        tid = f"resnode:{g.snapshot_id}:{edge.file_rel_path}:{edge.callee}:{edge.line}"
        if sid in g.nodes and tid in g.nodes:
            g.add_edge(sid, "CALLS_RESOLVED" if edge.resolution_kind == "STATIC" else "CALLS_UNKNOWN", tid, {})


def build_analysis_graph(
    g: InMemoryGraph,
    manifest: RepoManifest,
    parse: ParseRunResult,
    settings: HunterSettings,
    *,
    wp_semantics_v2: bool = True,
    resolver_enabled: bool = True,
    cfg_ssa_enabled: bool = True,
    taint_path_sensitive: bool = True,
    security_popchain: bool = True,
    regex_taint_fallback: bool = False,
    structural_stats: StructuralImportStats | None = None,
) -> GraphBuildPipelineResult:
    result = GraphBuildPipelineResult(structural_stats=structural_stats)
    result.security_stats = augment_security_facts(
        g,
        parse,
        max_same_file_flow_edges_per_file=settings.analysis_max_same_file_flow_edges_per_file,
    )
    if wp_semantics_v2:
        result.wp_hooks = import_wordpress_semantics(g)
    if security_popchain:
        result.security_signals = augment_security_from_graph(g)

    resolution: ResolutionResult | None = None
    if resolver_enabled:
        resolution = build_resolution_from_graph(g)
        if len(resolution.nodes) < settings.semantic_max_functions:
            _export_resolution(g, resolution)
        result.resolution = resolution

    cfg = None
    ssa = None
    if cfg_ssa_enabled and resolution is not None:
        cfg = build_cfg(resolution, max_blocks=settings.semantic_max_cfg_blocks)
        ssa = build_ssa(cfg)
        for b in cfg.blocks:
            g.upsert_node(
                b.block_id,
                "CFGBlock",
                {"function_name": b.function_name, "file": b.file_rel_path, "line": b.line, "guard_kind": b.guard_kind},
            )
        for e in cfg.edges:
            if e.src in g.nodes and e.dst in g.nodes:
                g.add_edge(e.src, e.kind, e.dst, {})

    if regex_taint_fallback:
        augment_taint(g, manifest)
    if taint_path_sensitive and resolution is not None and cfg is not None and ssa is not None:
        result.interprocedural_edges = augment_taint_interprocedural(
            g,
            resolution=resolution,
            cfg=cfg,
            ssa=ssa,
            max_flow_edges=settings.taint_max_interprocedural_flow_edges,
        )

    lr = apply_layers(g)
    result.layer_counts = {"layered_nodes": lr.layered_nodes, "layered_edges": lr.layered_edges}
    return result
