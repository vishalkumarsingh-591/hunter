from __future__ import annotations

from hunter.graph.in_memory import InMemoryGraph


def check_integrity(g: InMemoryGraph) -> tuple[bool, list[str]]:
    """Return (ok, issues)."""
    issues: list[str] = []
    node_ids = set(g.nodes)
    for i, e in enumerate(g.edges):
        if e["src"] not in node_ids:
            issues.append(f"edge[{i}] missing src {e['src']}")
        if e["dst"] not in node_ids:
            issues.append(f"edge[{i}] missing dst {e['dst']}")
        if "layer_src" in e and "layer_dst" in e:
            if not e.get("layer_src") or not e.get("layer_dst"):
                issues.append(f"edge[{i}] incomplete layer metadata")
    for nid, n in g.nodes.items():
        if n.get("label") in {"CFGBlock", "SSAVariable", "PHINode"} and "layer" in n and n["layer"] != "L3_FEATURE_FLOW":
            issues.append(f"node {nid} unexpected layer assignment {n['layer']}")
    return len(issues) == 0, issues
