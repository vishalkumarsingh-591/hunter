from __future__ import annotations

from hunter.analysis.semantic.resolver_graph import build_resolution_from_graph
from hunter.graph.in_memory import InMemoryGraph


def test_resolver_index_finds_static_calls() -> None:
    g = InMemoryGraph(snapshot_id="snap1", schema_version="3.1")
    sid = "snap1"
    fid = f"file:{sid}:plugin.php"
    g.upsert_node(fid, "File", {"path": "plugin.php"})
    caller = f"func:{sid}:plugin.php:10:function_definition"
    call = f"callsite:{sid}:plugin.php:12:0"
    callee_sym = f"sym:{sid}:dangerous_fn"
    g.upsert_node(caller, "Function", {"name": "handler", "file": "plugin.php", "line": 10})
    g.upsert_node(call, "Callsite", {"label_preview": "dangerous_fn()", "file": "plugin.php", "line": 12})
    g.upsert_node(callee_sym, "Symbol", {"name": "dangerous_fn", "file": "plugin.php"})
    callee_fn = f"func:{sid}:plugin.php:40:function_definition"
    g.upsert_node(callee_fn, "Function", {"name": "dangerous_fn", "file": "plugin.php", "line": 40})
    g.add_edge(fid, "DEFINED_IN", caller)
    g.add_edge(fid, "HAS_CALLSITE", call)
    g.add_edge(caller, "CALLS", call)
    g.add_edge(call, "CALLS_TARGET", callee_sym)

    result = build_resolution_from_graph(g)
    static = [e for e in result.edges if e.resolution_kind == "STATIC"]
    assert len(static) == 1
    assert static[0].caller == "handler"
    assert static[0].callee == "dangerous_fn"
    assert result.unresolved_calls == 0
