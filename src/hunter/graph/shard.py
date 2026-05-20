"""Per-file graph shards and deterministic merge for parallel augmentation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunter.concurrency.pool import run_threaded_map
from hunter.graph.in_memory import InMemoryGraph
from hunter.graph.security_facts_catalog import (
    SecurityFactsStats,
    augment_security_facts_file,
    merge_catalogs,
)
from hunter.graph.structural_import import StructuralImportStats, import_structural_file
from hunter.graph.wp_import import import_wordpress_semantics_file
from hunter.models.ir import FileParseArtifact, ParseRunResult


@dataclass
class GraphShard:
    rel_path: str
    file_props: dict[str, Any] = field(default_factory=dict)
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[tuple[str, str, str, dict[str, Any] | None]] = field(default_factory=list)
    structural: StructuralImportStats = field(default_factory=StructuralImportStats)
    security: SecurityFactsStats = field(default_factory=SecurityFactsStats)
    wp_nodes: int = 0


@dataclass
class ParallelAugmentResult:
    structural_stats: StructuralImportStats
    security_stats: SecurityFactsStats
    wp_hooks: int


def _merge_stats_struct(base: StructuralImportStats, part: StructuralImportStats) -> None:
    base.functions += part.functions
    base.methods += part.methods
    base.classes += part.classes
    base.callsites += part.callsites
    base.truncated_files += part.truncated_files


def _merge_stats_security(base: SecurityFactsStats, part: SecurityFactsStats) -> None:
    base.sources += part.sources
    base.sinks += part.sinks
    base.sanitizers += part.sanitizers


def merge_shards(g: InMemoryGraph, shards: list[GraphShard]) -> None:
    fid_prefix = f"file:{g.snapshot_id}:"
    for shard in sorted(shards, key=lambda s: s.rel_path):
        fid = f"{fid_prefix}{shard.rel_path}"
        if shard.file_props and fid in g.nodes:
            g.nodes[fid].update(shard.file_props)
        g.bulk_add(shard.nodes, shard.edges)


@dataclass
class _ShardJob:
    rel_path: str
    art: FileParseArtifact
    sid: str
    catalog_ids: list[str]
    compiled: list
    heuristics: list
    wp_enabled: bool


def _build_shard(job: _ShardJob) -> GraphShard:
    shard = GraphShard(rel_path=job.rel_path)
    fp, nodes, edges, st = import_structural_file(job.sid, job.rel_path, job.art)
    shard.file_props = fp
    shard.nodes = nodes
    shard.edges = edges
    shard.structural = st
    sec = augment_security_facts_file(
        job.sid,
        job.rel_path,
        job.art,
        nodes,
        edges,
        compiled=job.compiled,
        heuristics=job.heuristics,
    )
    shard.security = sec.stats
    shard.nodes.update(sec.nodes)
    shard.edges.extend(sec.edges)
    if job.wp_enabled and job.art.language == "php":
        wp_nodes, wp_edges, wp_count = import_wordpress_semantics_file(
            job.sid, job.rel_path, nodes, edges
        )
        shard.nodes.update(wp_nodes)
        shard.edges.extend(wp_edges)
        shard.wp_nodes = wp_count
    return shard


def parallel_augment_graph(
    g: InMemoryGraph,
    parse: ParseRunResult,
    *,
    catalog_ids: list[str],
    workers: int,
    wp_enabled: bool,
) -> ParallelAugmentResult:
    _merged, compiled = merge_catalogs(catalog_ids)
    heuristics = _merged.heuristic_patterns
    sid = g.snapshot_id
    jobs = [
        _ShardJob(
            rel_path=rel_path,
            art=art,
            sid=sid,
            catalog_ids=catalog_ids,
            compiled=compiled,
            heuristics=heuristics,
            wp_enabled=wp_enabled,
        )
        for rel_path, art in sorted(parse.per_file.items())
        if f"file:{sid}:{rel_path}" in g.nodes
    ]
    shards = run_threaded_map(jobs, _build_shard, workers=workers)
    merge_shards(g, shards)
    struct = StructuralImportStats()
    sec = SecurityFactsStats()
    wp_total = 0
    for shard in shards:
        _merge_stats_struct(struct, shard.structural)
        _merge_stats_security(sec, shard.security)
        wp_total += shard.wp_nodes
    return ParallelAugmentResult(structural_stats=struct, security_stats=sec, wp_hooks=wp_total)
