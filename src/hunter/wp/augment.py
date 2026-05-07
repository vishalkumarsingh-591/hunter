from __future__ import annotations

import re
from pathlib import Path

from hunter.graph.in_memory import InMemoryGraph
from hunter.models.core import RepoManifest

_ADD_HOOK = re.compile(
    r"""add_(?P<kind>action|filter)\s*\(\s*['"](?P<hook>[^'"]+)['"]""",
    re.MULTILINE,
)
_REST = re.compile(
    r"""register_rest_route\s*\(\s*['"](?P<ns>[^'"]+)['"]\s*,\s*['"](?P<route>[^'"]+)['"]""",
    re.MULTILINE,
)
_CAP = re.compile(r"""current_user_can\s*\(\s*['"](?P<cap>[a-zA-Z0-9_]+)['"]""", re.MULTILINE)
_NONCE = re.compile(
    r"""(check_ajax_referer|wp_verify_nonce|check_admin_referer)\s*\(""",
    re.MULTILINE,
)


def _line_of_offset(source: str, byte_off: int) -> int:
    return source.count("\n", 0, min(byte_off, len(source))) + 1


def augment_wordpress_semantics(g: InMemoryGraph, manifest: RepoManifest) -> None:
    """Add WordPress semantic nodes and edges deterministically from PHP sources."""
    root = Path(manifest.root_path_norm)
    for mf in manifest.files:
        if mf.language_guess != "php" or mf.parse_policy != "parse":
            continue
        path = root / mf.rel_path
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fid = f"file:{g.snapshot_id}:{mf.rel_path}"
        for m in _ADD_HOOK.finditer(text):
            hook = m.group("hook")
            kind = m.group("kind")
            byte_off = m.start()
            line = _line_of_offset(text, byte_off)
            hid = f"hook:{g.snapshot_id}:{mf.rel_path}:{hook}:{line}"
            g.upsert_node(
                hid,
                "HookRegistration",
                {"hook": hook, "register_kind": kind, "line": line, "file": mf.rel_path},
            )
            g.add_edge(fid, "HAS_HOOK", hid, {})
            if hook.startswith("wp_ajax_nopriv_"):
                aid = f"ajax:{g.snapshot_id}:{mf.rel_path}:{hook}:{line}"
                g.upsert_node(
                    aid,
                    "AjaxAction",
                    {
                        "action": hook.removeprefix("wp_ajax_nopriv_"),
                        "nopriv": True,
                        "line": line,
                        "file": mf.rel_path,
                    },
                )
                g.add_edge(hid, "IMPLEMENTS_AJAX", aid, {})
            elif hook.startswith("wp_ajax_") and not hook.startswith("wp_ajax_nopriv_"):
                aid = f"ajax:{g.snapshot_id}:{mf.rel_path}:{hook}:{line}"
                g.upsert_node(
                    aid,
                    "AjaxAction",
                    {"action": hook.removeprefix("wp_ajax_"), "nopriv": False, "line": line, "file": mf.rel_path},
                )
                g.add_edge(hid, "IMPLEMENTS_AJAX", aid, {})
        for m in _REST.finditer(text):
            ns, route = m.group("ns"), m.group("route")
            line = _line_of_offset(text, m.start())
            rid = f"route:{g.snapshot_id}:{mf.rel_path}:{ns}:{route}:{line}"
            g.upsert_node(
                rid,
                "Route",
                {"namespace": ns, "route": route, "line": line, "permission_callback": "unknown"},
            )
            g.add_edge(fid, "HAS_ROUTE", rid, {})
        for m in _CAP.finditer(text):
            cap = m.group("cap")
            line = _line_of_offset(text, m.start())
            cid = f"capcheck:{g.snapshot_id}:{mf.rel_path}:{cap}:{line}"
            g.upsert_node(cid, "CapabilityCheck", {"capability": cap, "line": line, "file": mf.rel_path})
            g.add_edge(fid, "HAS_CAP_CHECK", cid, {})
        if _NONCE.search(text):
            nid = f"nonce:{g.snapshot_id}:{mf.rel_path}"
            g.upsert_node(nid, "NonceGuardApprox", {"file": mf.rel_path})
            g.add_edge(fid, "HAS_NONCE_GUARD", nid, {})
