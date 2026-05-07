from __future__ import annotations

import hashlib
from dataclasses import dataclass

from hunter.graph.in_memory import InMemoryGraph
from hunter.graph.integrity import check_integrity
from hunter.models.core import RepoManifest
from hunter.models.ir import ParseRunResult


@dataclass
class GraphBuildResult:
    graph: InMemoryGraph
    integrity_ok: bool
    integrity_issues: list[str]


def _snapshot_id(manifest_sha256: str, parser_lock: str) -> str:
    return hashlib.sha256(f"{manifest_sha256}|{parser_lock}".encode()).hexdigest()[:24]


def build_graph_from_parse(
    manifest: RepoManifest,
    parse: ParseRunResult,
    schema_version: str,
) -> GraphBuildResult:
    sid = _snapshot_id(manifest.manifest_sha256, parse.parser_lock_hash)
    g = InMemoryGraph(snapshot_id=sid, schema_version=schema_version)
    repo_id = f"repo:{hashlib.sha256(manifest.root_path_norm.encode()).hexdigest()[:16]}"
    g.upsert_node(repo_id, "Repository", {"path": manifest.root_path_norm})
    g.upsert_node(sid, "Snapshot", {"manifest_sha256": manifest.manifest_sha256})
    g.add_edge(repo_id, "HAS_SNAPSHOT", sid, {})
    for mf in manifest.files:
        fid = f"file:{sid}:{mf.rel_path}"
        g.upsert_node(
            fid,
            "File",
            {
                "path": mf.rel_path,
                "sha256": mf.sha256,
                "size": mf.size,
                "language": mf.language_guess,
            },
        )
        g.add_edge(sid, "IN_SNAPSHOT", fid, {})
        art = parse.per_file.get(mf.rel_path)
        if not art:
            continue
        for ir in art.ir_nodes:
            gid = f"ir:{sid}:{ir.id}"
            g.upsert_node(
                gid,
                "IRNode",
                {
                    "ir_id": ir.id,
                    "kind": ir.kind,
                    "start_line": ir.start_line,
                    "end_line": ir.end_line,
                    "start_byte": ir.start_byte,
                    "end_byte": ir.end_byte,
                    "label_preview": ir.label[:120],
                },
            )
            g.add_edge(fid, "CONTAINS_IR", gid, {})
    ok, issues = check_integrity(g)
    return GraphBuildResult(graph=g, integrity_ok=ok, integrity_issues=issues)
