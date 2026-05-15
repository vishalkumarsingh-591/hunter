"""Graph traversals for rule evaluators (no filesystem reads)."""

from __future__ import annotations

from hunter.graph.in_memory import InMemoryGraph


def flows_to_edges(g: InMemoryGraph) -> list[dict]:
    return [e for e in g.edges if e["rel"] == "FLOWS_TO" and e.get("via") in {"same_file_ordering", "interprocedural"}]


def source_sink_pair(g: InMemoryGraph, src: str, dst: str) -> tuple[dict, dict] | None:
    sn, sk = g.nodes.get(src, {}), g.nodes.get(dst, {})
    if sn.get("label") != "Source" or sk.get("label") != "Sink":
        return None
    return sn, sk


def sanitizers_in_file_before_line(g: InMemoryGraph, file_rel: str, before_line: int) -> list[str]:
    out: list[str] = []
    for nid, n in g.nodes.items():
        if n.get("label") != "Sanitizer":
            continue
        if n.get("file") != file_rel:
            continue
        line = int(n.get("line", 0))
        if 0 < line <= before_line:
            out.append(nid)
    return sorted(out)


def has_sql_prepare_between(g: InMemoryGraph, file_rel: str, source_line: int, sink_line: int) -> bool:
    for nid, n in g.nodes.items():
        if n.get("label") != "Sanitizer":
            continue
        if n.get("file") != file_rel:
            continue
        if n.get("context") != "SQL" and n.get("kind") != "SQL_PREPARE":
            continue
        line = int(n.get("line", 0))
        if source_line < line <= sink_line:
            return True
    return False


def heuristic_patterns(g: InMemoryGraph, pattern: str) -> list[tuple[str, dict]]:
    return [
        (nid, n)
        for nid, n in g.nodes.items()
        if n.get("label") == "HeuristicPattern" and n.get("pattern") == pattern
    ]
