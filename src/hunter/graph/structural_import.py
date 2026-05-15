"""Import structure-complete symbols from parse IR into the graph."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from hunter.graph.in_memory import InMemoryGraph
from hunter.models.ir import ParseRunResult

_FN_IR_KINDS = frozenset(
    {"function_definition", "method_declaration", "function", "arrow_function", "function_declaration"}
)
_CLASS_IR_KINDS = frozenset({"class_declaration", "interface_declaration", "trait_declaration"})
_CALL_IR_KINDS = frozenset({"call_expression", "scoped_call_expression", "member_call_expression"})

_DEFAULT_VENDOR_SKIP_GLOBS = (
    "**/*.min.js",
    "**/vendor/**",
    "**/node_modules/**",
)


def _path_matches_globs(rel_path: str, globs: tuple[str, ...]) -> bool:
    norm = rel_path.replace("\\", "/")
    return any(fnmatch.fnmatch(norm, g) for g in globs)


def skip_vendor_structural(rel_path: str, globs: tuple[str, ...] | None = None) -> bool:
    return _path_matches_globs(rel_path, globs or _DEFAULT_VENDOR_SKIP_GLOBS)


@dataclass
class StructuralImportStats:
    functions: int = 0
    methods: int = 0
    classes: int = 0
    callsites: int = 0
    truncated_files: int = 0


def _graph_ir_id(snapshot_id: str, ir_id: str) -> str:
    return f"ir:{snapshot_id}:{ir_id}"


def _static_callee_name(label: str) -> str | None:
    m = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", label)
    return m.group(1) if m else None


def import_structural(
    g: InMemoryGraph,
    parse: ParseRunResult,
    *,
    vendor_skip_globs: tuple[str, ...] | None = None,
) -> StructuralImportStats:
    sid = g.snapshot_id
    stats = StructuralImportStats()
    for rel_path, art in sorted(parse.per_file.items()):
        skip_callsites = skip_vendor_structural(rel_path, vendor_skip_globs)
        fid = f"file:{sid}:{rel_path}"
        if fid not in g.nodes:
            continue
        truncated = art.status == "PARTIAL" or any(d.code == "IR_BUDGET_EXCEEDED" for d in art.diagnostics)
        g.nodes[fid]["parse_status"] = art.status
        g.nodes[fid]["ir_node_count"] = len(art.ir_nodes)
        g.nodes[fid]["lift_truncated"] = truncated
        if truncated:
            stats.truncated_files += 1

        ir_to_graph = {ir.id: _graph_ir_id(sid, ir.id) for ir in art.ir_nodes}
        ir_id_to_entity: dict[str, str] = {}

        for ir in art.ir_nodes:
            gid = ir_to_graph[ir.id]
            if ir.kind in _CLASS_IR_KINDS:
                cid = f"class:{sid}:{rel_path}:{ir.start_line}:{ir.kind}"
                g.upsert_node(
                    cid,
                    "Class",
                    {"name": ir.label[:120], "kind": ir.kind, "line": ir.start_line, "file": rel_path, "ir_node_id": ir.id},
                )
                g.add_edge(fid, "DEFINED_IN", cid, {})
                g.add_edge(cid, "ANCHORED_AT", gid, {})
                ir_id_to_entity[ir.id] = cid
                stats.classes += 1
            elif ir.kind in _FN_IR_KINDS:
                label = "Method" if ir.kind == "method_declaration" else "Function"
                nid = f"func:{sid}:{rel_path}:{ir.start_line}:{ir.kind}"
                g.upsert_node(
                    nid,
                    label,
                    {"name": ir.label[:120], "kind": ir.kind, "line": ir.start_line, "file": rel_path, "ir_node_id": ir.id},
                )
                g.add_edge(fid, "DEFINED_IN", nid, {})
                g.add_edge(nid, "ANCHORED_AT", gid, {})
                ir_id_to_entity[ir.id] = nid
                if label == "Method":
                    stats.methods += 1
                else:
                    stats.functions += 1
            elif ir.kind in _CALL_IR_KINDS and not skip_callsites:
                cid = f"callsite:{sid}:{rel_path}:{ir.start_line}:{ir.start_byte}"
                g.upsert_node(
                    cid,
                    "Callsite",
                    {
                        "label_preview": ir.label[:120],
                        "line": ir.start_line,
                        "file": rel_path,
                        "ir_node_id": ir.id,
                    },
                )
                g.add_edge(fid, "HAS_CALLSITE", cid, {})
                g.add_edge(cid, "ANCHORED_AT", gid, {})
                ir_id_to_entity[ir.id] = cid
                stats.callsites += 1

        for edge in art.ir_edges:
            if edge.kind == "CONTAINS":
                src_ent = ir_id_to_entity.get(edge.src_id)
                dst_ent = ir_id_to_entity.get(edge.dst_id)
                if src_ent and dst_ent:
                    g.add_edge(src_ent, "CONTAINS", dst_ent, {})
            elif edge.kind == "CALLS":
                parent = ir_id_to_entity.get(edge.src_id)
                call = ir_id_to_entity.get(edge.dst_id)
                if parent and call:
                    g.add_edge(parent, "CALLS", call, {})
                    callee = _static_callee_name(str(g.nodes[call].get("label_preview", "")))
                    if callee:
                        sym = f"sym:{sid}:{callee}"
                        g.upsert_node(sym, "Symbol", {"name": callee, "file": rel_path})
                        g.add_edge(call, "CALLS_TARGET", sym, {"name": callee})
                    else:
                        unk = f"unknown:{call}"
                        call_node = g.nodes.get(call, {})
                        g.upsert_node(
                            unk,
                            "UnknownTarget",
                            {
                                "callsite_id": call,
                                "file": rel_path,
                                "line": int(call_node.get("line", 0)),
                            },
                        )
                        g.add_edge(call, "CALLS_UNKNOWN", unk, {})

    return stats
