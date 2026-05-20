"""WordPress semantics from graph IR/callsite nodes (no plugin file reads)."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from hunter.graph.in_memory import InMemoryGraph
from hunter.models.core import RepoManifest

_ADD_HOOK = re.compile(r"add_(action|filter)\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
_AJAX_NOPRIV = re.compile(r"wp_ajax_nopriv_([a-zA-Z0-9_-]+)", re.I)
_REST = re.compile(r"register_rest_route\s*\(", re.I)
_WEAK_PERM = re.compile(r"permission_callback\s*=>\s*['\"]__return_true['\"]|__return_true", re.I)
_CAP = re.compile(r"current_user_can\s*\(", re.I)
_NONCE = re.compile(r"(check_ajax_referer|wp_verify_nonce|check_admin_referer)\s*\(", re.I)


def _file_text_blob(g: InMemoryGraph, sid: str, file_rel: str) -> str:
    parts: list[tuple[tuple[int, int, str], str]] = []
    fid = f"file:{sid}:{file_rel}"
    for e in g.edges:
        if e["src"] == fid and e["rel"] == "CONTAINS_IR":
            n = g.nodes.get(e["dst"], {})
            preview = str(n.get("label_preview", ""))
            if preview:
                line = int(n.get("start_line", 0))
                parts.append(((line, 0, preview), preview))
    for nid in sorted(g.nodes):
        n = g.nodes[nid]
        if n.get("file") != file_rel:
            continue
        if str(nid).startswith(f"callsite:{sid}:"):
            preview = str(n.get("label_preview", ""))
            if preview:
                line = int(n.get("line", 0))
                parts.append(((line, 1, preview), preview))
        elif n.get("label") in ("Function", "Method"):
            name = str(n.get("name", ""))
            if name:
                line = int(n.get("line", 0))
                parts.append(((line, 2, name), name))
    parts.sort(key=lambda x: x[0])
    return "\n".join(text for _, text in parts)


def import_wordpress_semantics(g: InMemoryGraph) -> int:
    """Returns count of hook nodes created."""
    sid = g.snapshot_id
    count = 0
    files = sorted({str(n.get("file", "")) for n in g.nodes.values() if n.get("file")})

    for file_rel in files:
        if not file_rel:
            continue
        fid = f"file:{sid}:{file_rel}"
        if fid not in g.nodes:
            continue
        text = _file_text_blob(g, sid, file_rel)
        if not text.strip():
            continue

        for m in _ADD_HOOK.finditer(text):
            hook = m.group(2)
            kind = m.group(1).lower()
            line = text.count("\n", 0, m.start()) + 1
            hid = f"hook:{sid}:{file_rel}:{hook}:{line}"
            g.upsert_node(
                hid, "HookRegistration", {"hook": hook, "register_kind": kind, "line": line, "file": file_rel}
            )
            g.add_edge(fid, "HAS_HOOK", hid, {})
            count += 1

        for m in _AJAX_NOPRIV.finditer(text):
            hook = f"wp_ajax_nopriv_{m.group(1)}"
            line = text.count("\n", 0, m.start()) + 1
            aid = f"ajax:{sid}:{file_rel}:{hook}:{line}"
            guard_id = f"guardcheck:{aid}"
            g.upsert_node(
                aid,
                "AjaxAction",
                {"action": m.group(1), "nopriv": True, "line": line, "file": file_rel, "hook": hook},
            )
            g.upsert_node(guard_id, "GuardCheck", {"reason": "nopriv_surface", "file": file_rel})
            g.add_edge(fid, "HAS_AJAX", aid, {})
            g.add_edge(aid, "MISSING_GUARD", guard_id, {"reason": "nopriv_surface"})
            count += 1

        if _REST.search(text):
            rid = f"route:{sid}:{file_rel}"
            g.upsert_node(rid, "Route", {"file": file_rel, "permission_callback": "unknown"})
            g.add_edge(fid, "HAS_ROUTE", rid, {})
            if _WEAK_PERM.search(text):
                weak_id = f"weakperm:{rid}"
                g.upsert_node(weak_id, "GuardCheck", {"reason": "weak_rest_permission", "file": file_rel})
                g.add_edge(rid, "MISSING_GUARD", weak_id, {"reason": "weak_rest_permission"})
            count += 1

        if _CAP.search(text):
            cid = f"capv2:{sid}:{file_rel}"
            g.upsert_node(cid, "CapabilityCheck", {"file": file_rel, "inferred": True})
            g.add_edge(fid, "HAS_CAP_CHECK", cid, {})
        elif _NONCE.search(text):
            nid = f"nonce:{sid}:{file_rel}"
            g.upsert_node(nid, "NonceGuardApprox", {"file": file_rel})
            g.add_edge(fid, "HAS_NONCE_GUARD", nid, {})

    return count


def _text_blob_from_nodes(nodes: dict[str, dict[str, Any]], file_rel: str) -> str:
    parts: list[tuple[tuple[int, int, str], str]] = []
    for nid in sorted(nodes):
        n = nodes[nid]
        if n.get("file") != file_rel:
            continue
        if n.get("label") == "Callsite":
            preview = str(n.get("label_preview", ""))
            if preview:
                line = int(n.get("line", 0))
                parts.append(((line, 0, preview), preview))
        elif n.get("label") in ("Function", "Method"):
            name = str(n.get("name", ""))
            if name:
                line = int(n.get("line", 0))
                parts.append(((line, 2, name), name))
    parts.sort(key=lambda x: x[0])
    return "\n".join(text for _, text in parts)


def import_wordpress_semantics_file(
    sid: str,
    file_rel: str,
    nodes: dict[str, dict[str, Any]],
    edges: list[tuple[str, str, str, dict | None]],
) -> tuple[dict[str, dict[str, Any]], list[tuple[str, str, str, dict | None]], int]:
    """WordPress hook/ajax/route nodes for one PHP file (parallel shard)."""
    out_nodes: dict[str, dict[str, Any]] = {}
    out_edges: list[tuple[str, str, str, dict | None]] = []
    count = 0
    fid = f"file:{sid}:{file_rel}"
    text = _text_blob_from_nodes(nodes, file_rel)
    if not text.strip():
        return out_nodes, out_edges, 0

    def add_node(nid: str, label: str, props: dict) -> None:
        out_nodes[nid] = {"id": nid, "label": label, **props}

    def add_edge(src: str, rel: str, dst: str, props: dict | None = None) -> None:
        out_edges.append((src, rel, dst, props))

    for m in _ADD_HOOK.finditer(text):
        hook = m.group(2)
        kind = m.group(1).lower()
        line = text.count("\n", 0, m.start()) + 1
        hid = f"hook:{sid}:{file_rel}:{hook}:{line}"
        add_node(hid, "HookRegistration", {"hook": hook, "register_kind": kind, "line": line, "file": file_rel})
        add_edge(fid, "HAS_HOOK", hid)
        count += 1

    for m in _AJAX_NOPRIV.finditer(text):
        hook = f"wp_ajax_nopriv_{m.group(1)}"
        line = text.count("\n", 0, m.start()) + 1
        aid = f"ajax:{sid}:{file_rel}:{hook}:{line}"
        guard_id = f"guardcheck:{aid}"
        add_node(
            aid,
            "AjaxAction",
            {"action": m.group(1), "nopriv": True, "line": line, "file": file_rel, "hook": hook},
        )
        add_node(guard_id, "GuardCheck", {"reason": "nopriv_surface", "file": file_rel})
        add_edge(fid, "HAS_AJAX", aid)
        add_edge(aid, "MISSING_GUARD", guard_id, {"reason": "nopriv_surface"})
        count += 1

    if _REST.search(text):
        rid = f"route:{sid}:{file_rel}"
        add_node(rid, "Route", {"file": file_rel, "permission_callback": "unknown"})
        add_edge(fid, "HAS_ROUTE", rid)
        if _WEAK_PERM.search(text):
            weak_id = f"weakperm:{rid}"
            add_node(weak_id, "GuardCheck", {"reason": "weak_rest_permission", "file": file_rel})
            add_edge(rid, "MISSING_GUARD", weak_id, {"reason": "weak_rest_permission"})
        count += 1

    if _CAP.search(text):
        cid = f"capv2:{sid}:{file_rel}"
        add_node(cid, "CapabilityCheck", {"file": file_rel, "inferred": True})
        add_edge(fid, "HAS_CAP_CHECK", cid)
    elif _NONCE.search(text):
        nid = f"nonce:{sid}:{file_rel}"
        add_node(nid, "NonceGuardApprox", {"file": file_rel})
        add_edge(fid, "HAS_NONCE_GUARD", nid)

    return out_nodes, out_edges, count


_ENTRYPOINT_MARKERS = (
    "index.php",
    "public/index.php",
    "wp-load.php",
    "wp-admin/admin-ajax.php",
)


def detect_entrypoints(g: InMemoryGraph, manifest: RepoManifest) -> int:
    """Stub: mark known entrypoint files on the graph (no reachability gating in 2.1)."""
    sid = g.snapshot_id
    count = 0
    for mf in manifest.files:
        norm = mf.rel_path.replace("\\", "/").lower()
        matched = next((m for m in _ENTRYPOINT_MARKERS if norm.endswith(m)), None)
        if not matched:
            continue
        fid = f"file:{sid}:{mf.rel_path}"
        if fid not in g.nodes:
            continue
        eid = f"entrypoint:{sid}:{mf.rel_path}"
        g.upsert_node(
            eid,
            "Entrypoint",
            {"file": mf.rel_path, "marker": matched, "surface": "UNKNOWN"},
        )
        g.add_edge(fid, "HAS_ENTRYPOINT", eid, {})
        count += 1
    return count


def run_platform_adapters(g: InMemoryGraph, manifest: RepoManifest, adapter_ids: list[str]) -> dict[str, int]:
    results: dict[str, int] = {}
    for aid in adapter_ids:
        fn = PLATFORM_ADAPTERS.get(aid)
        if fn is None:
            continue
        results[aid] = fn(g, manifest)
    return results


def _adapter_wordpress(g: InMemoryGraph, manifest: RepoManifest) -> int:
    hooks = import_wordpress_semantics(g)
    return hooks + detect_entrypoints(g, manifest)


PLATFORM_ADAPTERS: dict[str, Callable[[InMemoryGraph, RepoManifest], int]] = {
    "wordpress": _adapter_wordpress,
}
