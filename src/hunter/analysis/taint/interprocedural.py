"""Bounded interprocedural flow edges between existing Source/Sink nodes."""

from __future__ import annotations

from hunter.analysis.semantic.cfg import CFGResult
from hunter.analysis.semantic.resolver import ResolutionResult
from hunter.analysis.semantic.ssa import SSAResult
from hunter.graph.in_memory import InMemoryGraph

# HTTP sources may reach these sink kinds cross-file; file-include/upload excluded as too noisy.
_ALLOWED_CROSS_FILE: dict[str, frozenset[str]] = {
    "HTTP_SUPERGLOBAL": frozenset({"SQL", "HTML", "REDIRECT", "HTTP_CLIENT", "CODE_EXEC", "OBJECT_INJECTION"}),
}


def _source_kind(n: dict) -> str:
    return str(n.get("kind", "HTTP_SUPERGLOBAL"))


def _pair_allowed(sn: dict, sk: dict) -> bool:
    skind = str(sk.get("kind", ""))
    allowed = _ALLOWED_CROSS_FILE.get(_source_kind(sn), frozenset())
    return skind in allowed


def augment_taint_interprocedural(
    g: InMemoryGraph,
    *,
    resolution: ResolutionResult,
    cfg: CFGResult,
    ssa: SSAResult,
    max_flow_edges: int = 5_000,
) -> int:
    """
    Add cross-file FLOWS_TO approximations with caps.
    Returns count of new FLOWS_TO edges added.
    """
    sinks = sorted(
        (nid for nid, n in g.nodes.items() if n.get("label") == "Sink"),
        key=lambda x: (str(g.nodes[x].get("file", "")), int(g.nodes[x].get("line", 0)), x),
    )
    sources = sorted(
        (nid for nid, n in g.nodes.items() if n.get("label") == "Source"),
        key=lambda x: (str(g.nodes[x].get("file", "")), int(g.nodes[x].get("line", 0)), x),
    )
    if not sinks or not sources:
        return 0

    existing: set[tuple[str, str]] = {(e["src"], e["dst"]) for e in g.edges if e["rel"] == "FLOWS_TO"}

    unresolved_penalty = 1 if resolution.unresolved_calls > 0 else 0
    phi_count = len(ssa.phi_nodes)
    unknown_branch_count = sum(1 for e in cfg.edges if e.kind == "UNKNOWN_BRANCH")
    constraint_strength = max(0, 100 - (unresolved_penalty * 30 + unknown_branch_count + phi_count // 2))

    added = 0
    for sid in sources:
        sn = g.nodes[sid]
        sfile = str(sn.get("file", ""))
        for kid in sinks:
            if (sid, kid) in existing:
                continue
            sk = g.nodes[kid]
            kfile = str(sk.get("file", ""))
            if sfile and kfile and sfile == kfile:
                continue
            if not _pair_allowed(sn, sk):
                continue
            if sk.get("static_arg") or sk.get("static_path_likely"):
                continue
            if added >= max_flow_edges:
                return added
            g.add_edge(
                sid,
                "CAN_REACH_SINK",
                kid,
                {
                    "interprocedural": True,
                    "path_sensitive": True,
                    "constraint_strength": constraint_strength,
                    "unresolved_calls": resolution.unresolved_calls,
                    "phi_nodes": phi_count,
                },
            )
            g.add_edge(
                sid,
                "FLOWS_TO",
                kid,
                {
                    "via": "interprocedural",
                    "approx": True,
                    "interprocedural": True,
                    "path_sensitive": True,
                    "constraint_strength": constraint_strength,
                    "unresolved_calls": resolution.unresolved_calls,
                    "phi_nodes": phi_count,
                },
            )
            existing.add((sid, kid))
            added += 1
    return added
