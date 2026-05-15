"""Security signals derived from graph Sink nodes (no file reads)."""

from __future__ import annotations

from hunter.graph.in_memory import InMemoryGraph


def augment_security_from_graph(g: InMemoryGraph) -> int:
    count = 0
    for nid, n in g.nodes.items():
        if n.get("label") != "Sink":
            continue
        kind = str(n.get("kind", ""))
        file_rel = str(n.get("file", ""))
        line = int(n.get("line", 0))
        fid = f"file:{g.snapshot_id}:{file_rel}"
        if kind == "OBJECT_INJECTION":
            sig = f"objinj:{nid}"
            g.upsert_node(sig, "SecuritySignal", {"signal": "OBJECT_INJECTION_ENTRYPOINT", "file": file_rel, "line": line})
            g.add_edge(fid, "HAS_SECURITY_SIGNAL", sig, {})
            count += 1
        elif kind == "CODE_EXEC":
            sig = f"dang:{nid}"
            g.upsert_node(sig, "SecuritySignal", {"signal": "REACHABLE_DANGEROUS_SINK_CANDIDATE", "file": file_rel, "line": line})
            g.add_edge(fid, "HAS_SECURITY_SIGNAL", sig, {})
            count += 1
        elif kind == "UPLOAD":
            sig = f"upload:{nid}"
            g.upsert_node(sig, "SecuritySignal", {"signal": "UPLOAD_LIFECYCLE", "file": file_rel, "line": line})
            g.add_edge(fid, "HAS_SECURITY_SIGNAL", sig, {})
            count += 1
    return count
