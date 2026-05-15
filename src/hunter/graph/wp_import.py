"""WordPress semantics from graph IR/callsite nodes (no plugin file reads)."""

from __future__ import annotations

import re

from hunter.graph.in_memory import InMemoryGraph

_ADD_HOOK = re.compile(r"add_(action|filter)\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
_AJAX_NOPRIV = re.compile(r"wp_ajax_nopriv_([a-zA-Z0-9_-]+)", re.I)
_REST = re.compile(r"register_rest_route\s*\(", re.I)
_WEAK_PERM = re.compile(r"permission_callback\s*=>\s*['\"]__return_true['\"]|__return_true", re.I)
_CAP = re.compile(r"current_user_can\s*\(", re.I)
_NONCE = re.compile(r"(check_ajax_referer|wp_verify_nonce|check_admin_referer)\s*\(", re.I)


def _file_text_blob(g: InMemoryGraph, sid: str, file_rel: str) -> str:
    parts: list[str] = []
    fid = f"file:{sid}:{file_rel}"
    for e in g.edges:
        if e["src"] == fid and e["rel"] == "CONTAINS_IR":
            n = g.nodes.get(e["dst"], {})
            preview = str(n.get("label_preview", ""))
            if preview:
                parts.append(preview)
    for nid, n in g.nodes.items():
        if n.get("file") != file_rel:
            continue
        if str(nid).startswith(f"callsite:{sid}:"):
            parts.append(str(n.get("label_preview", "")))
        elif n.get("label") in ("Function", "Method"):
            parts.append(str(n.get("name", "")))
    return "\n".join(p for p in parts if p)


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
            g.upsert_node(hid, "HookRegistration", {"hook": hook, "register_kind": kind, "line": line, "file": file_rel})
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
