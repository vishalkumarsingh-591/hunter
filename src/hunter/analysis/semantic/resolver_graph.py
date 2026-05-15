"""Build interprocedural resolution from structure-complete graph (no file reads)."""

from __future__ import annotations

from hunter.analysis.semantic.resolver import ResolutionEdge, ResolutionNode, ResolutionResult
from hunter.graph.in_memory import InMemoryGraph


def build_resolution_from_graph(g: InMemoryGraph) -> ResolutionResult:
    result = ResolutionResult()
    fn_index: dict[str, list[tuple[str, int, str]]] = {}
    for nid, n in g.nodes.items():
        if n.get("label") not in ("Function", "Method"):
            continue
        name = str(n.get("name", ""))[:80]
        if not name:
            continue
        file_rel = str(n.get("file", ""))
        line = int(n.get("line", 0))
        result.nodes.append(ResolutionNode(function_name=name, file_rel_path=file_rel, line=line))
        fn_index.setdefault(name, []).append((file_rel, line, nid))

    for e in g.edges:
        if e["rel"] != "CALLS":
            continue
        caller_n = g.nodes.get(e["src"], {})
        call_n = g.nodes.get(e["dst"], {})
        if caller_n.get("label") not in ("Function", "Method"):
            continue
        if call_n.get("label") != "Callsite" and not str(e["dst"]).startswith("callsite:"):
            continue
        caller = str(caller_n.get("name", ""))[:80]
        file_rel = str(call_n.get("file", ""))
        line = int(call_n.get("line", 0))
        callee = None
        for e2 in g.edges:
            if e2["src"] == e["dst"] and e2["rel"] == "CALLS_TARGET":
                callee = str(g.nodes.get(e2["dst"], {}).get("name", ""))
                break
        if callee and callee in fn_index:
            result.edges.append(
                ResolutionEdge(
                    caller=caller,
                    callee=callee,
                    file_rel_path=file_rel,
                    line=line,
                    resolution_kind="STATIC",
                )
            )
        else:
            result.unresolved_calls += 1
            result.edges.append(
                ResolutionEdge(
                    caller=caller,
                    callee=callee or "unknown",
                    file_rel_path=file_rel,
                    line=line,
                    resolution_kind="UNKNOWN",
                )
            )

    result.nodes.sort(key=lambda n: (n.file_rel_path, n.line, n.function_name))
    result.edges.sort(key=lambda e: (e.file_rel_path, e.line, e.caller, e.callee, e.resolution_kind))
    return result
