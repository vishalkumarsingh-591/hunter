from __future__ import annotations

import re
from pathlib import Path
from dataclasses import dataclass

from hunter.graph.in_memory import InMemoryGraph
from hunter.models.core import RepoManifest

_ADD_HOOK = re.compile(r"add_(action|filter)\s*\(", re.MULTILINE)
_REST_PERMISSION = re.compile(
    r"register_rest_route\s*\([^,]+,\s*[^,]+,\s*\[[^\]]*['\"]permission_callback['\"]\s*=>\s*([^,\]]+)"
)
_CRON = re.compile(r"\bwp_schedule_event\s*\(")
_OPTION_WRITE = re.compile(r"\b(update_option|add_option|delete_option)\s*\(")
_UPLOAD = re.compile(r"\bwp_handle_upload\s*\(")
_NONCE_CHECK = re.compile(r"\b(check_ajax_referer|check_admin_referer|wp_verify_nonce)\s*\(")
_CAP_CHECK = re.compile(r"\b(current_user_can|user_can)\s*\(")
_MULTISITE = re.compile(r"\b(is_multisite|get_sites|switch_to_blog)\s*\(")
_FUNC_DEF = re.compile(r"(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


@dataclass(frozen=True)
class _FunctionDef:
    name: str
    kind: str
    file_rel: str
    line: int
    start: int
    end: int


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    in_single = False
    in_double = False
    escape = False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if in_single or in_double:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(text) - 1


def _collect_functions(text: str, file_rel: str) -> list[_FunctionDef]:
    defs: list[_FunctionDef] = []
    for m in _FUNC_DEF.finditer(text):
        start = m.start()
        open_idx = text.find("{", m.end())
        if open_idx == -1:
            continue
        end = _find_matching_brace(text, open_idx)
        line = _line(text, start)
        defs.append(_FunctionDef(name=m.group(1), kind="method" if "class " in text[max(0, start - 500):start] else "function", file_rel=file_rel, line=line, start=start, end=end))
    return defs


def _resolve_callback_expr(callback: str) -> str | None:
    raw = callback.strip().rstrip(")").strip()
    if not raw or raw.lower().startswith("function"):
        return None
    m = re.search(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*$", raw)
    if m:
        return m.group(1)
    m = re.search(r"->\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", raw)
    if m:
        return m.group(1)
    m = re.search(r"::\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", raw)
    if m:
        return m.group(1)
    m = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*$", raw)
    if m and m.group(1) not in {"array", "null", "true", "false"}:
        return m.group(1)
    return None


def _slice_guard_info(text: str, function_def: _FunctionDef) -> dict[str, object]:
    body = text[function_def.start : function_def.end + 1]
    has_cap = bool(_CAP_CHECK.search(body))
    has_nonce = bool(_NONCE_CHECK.search(body))
    return {
        "has_capability_guard": has_cap,
        "has_nonce_guard": has_nonce,
        "guard_kinds": [k for k, v in (("capability", has_cap), ("nonce", has_nonce)) if v],
        "body_start": function_def.start,
        "body_end": function_def.end,
    }


def _line(text: str, off: int) -> int:
    return text.count("\n", 0, max(0, off)) + 1


def augment_wordpress_semantics_v2(g: InMemoryGraph, manifest: RepoManifest) -> None:
    root = Path(manifest.root_path_norm)
    function_index: dict[str, list[_FunctionDef]] = {}
    file_text: dict[str, str] = {}

    for mf in manifest.files:
        if mf.language_guess != "php" or mf.parse_policy != "parse":
            continue
        p = root / mf.rel_path
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        file_text[mf.rel_path] = text
        for fn in _collect_functions(text, mf.rel_path):
            function_index.setdefault(fn.name, []).append(fn)

    for mf in manifest.files:
        if mf.language_guess != "php" or mf.parse_policy != "parse":
            continue
        p = root / mf.rel_path
        if not p.is_file():
            continue
        text = file_text.get(mf.rel_path) or p.read_text(encoding="utf-8", errors="replace")
        fid = f"file:{g.snapshot_id}:{mf.rel_path}"
        for m in _ADD_HOOK.finditer(text):
            open_idx = m.end() - 1
            depth = 1
            idx = open_idx + 1
            in_single = False
            in_double = False
            escape = False
            while idx < len(text) and depth > 0:
                ch = text[idx]
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == "'" and not in_double:
                    in_single = not in_single
                elif ch == '"' and not in_single:
                    in_double = not in_double
                elif not in_single and not in_double:
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                idx += 1
            call_text = text[open_idx + 1 : idx - 1 if idx > open_idx + 1 else idx]
            args = []
            current = []
            depth = 0
            in_single = False
            in_double = False
            escape = False
            for ch in call_text:
                if escape:
                    current.append(ch)
                    escape = False
                    continue
                if ch == "\\":
                    current.append(ch)
                    escape = True
                    continue
                if ch == "'" and not in_double:
                    in_single = not in_single
                elif ch == '"' and not in_single:
                    in_double = not in_double
                elif not in_single and not in_double:
                    if ch in "([{":
                        depth += 1
                    elif ch in ")]}" and depth > 0:
                        depth -= 1
                    elif ch == "," and depth == 0:
                        args.append("".join(current).strip())
                        current = []
                        continue
                current.append(ch)
            if current:
                args.append("".join(current).strip())
            if len(args) < 2:
                continue
            kind = "action" if "action" in call_text else "filter"
            hook = args[0].strip().strip("'\"")
            callback = args[1].strip()
            line = _line(text, m.start())
            hid = f"hookv2:{g.snapshot_id}:{mf.rel_path}:{hook}:{line}"
            g.upsert_node(
                hid,
                "HookRegistration",
                {"hook": hook, "register_kind": kind, "callback_expr": callback, "line": line, "file": mf.rel_path, "v2": True},
            )
            g.add_edge(fid, "HAS_HOOK", hid, {"v2": True})
            resolved_name = _resolve_callback_expr(callback)
            if resolved_name and resolved_name in function_index:
                for fn in function_index[resolved_name]:
                    handler_id = f"handler:{g.snapshot_id}:{fn.file_rel}:{fn.name}:{fn.line}"
                    handler_props = {
                        "name": fn.name,
                        "kind": fn.kind,
                        "line": fn.line,
                        "file": fn.file_rel,
                        "callback_expr": callback,
                        "v2": True,
                        **_slice_guard_info(file_text[fn.file_rel], fn),
                    }
                    g.upsert_node(handler_id, "HookHandler" if hook.startswith("wp_") else "Function", handler_props)
                    g.add_edge(hid, "HANDLED_BY", handler_id, {"callback_expr": callback, "v2": True})
            if "wp_ajax" in hook:
                aid = f"ajaxv2:{g.snapshot_id}:{mf.rel_path}:{hook}:{line}"
                g.upsert_node(
                    aid,
                    "AjaxAction",
                    {
                        "action": hook.split("wp_ajax_nopriv_")[-1] if "wp_ajax_nopriv_" in hook else hook.split("wp_ajax_")[-1],
                        "nopriv": hook.startswith("wp_ajax_nopriv_"),
                        "line": line,
                        "file": mf.rel_path,
                        "v2": True,
                    },
                )
                g.add_edge(hid, "IMPLEMENTS_AJAX", aid, {"v2": True})
                if resolved_name and resolved_name in function_index:
                    for fn in function_index[resolved_name]:
                        handler_id = f"handler:{g.snapshot_id}:{fn.file_rel}:{fn.name}:{fn.line}"
                        handler_props = {
                            "name": fn.name,
                            "kind": fn.kind,
                            "line": fn.line,
                            "file": fn.file_rel,
                            "callback_expr": callback,
                            "v2": True,
                            **_slice_guard_info(file_text[fn.file_rel], fn),
                        }
                        g.upsert_node(handler_id, "AjaxHandler", handler_props)
                        g.add_edge(aid, "HANDLED_BY", handler_id, {"callback_expr": callback, "v2": True})
        for m in _REST_PERMISSION.finditer(text):
            line = _line(text, m.start())
            rid = f"routev2:{g.snapshot_id}:{mf.rel_path}:{line}:{m.start()}"
            g.upsert_node(
                rid,
                "Route",
                {"permission_callback_expr": m.group(1).strip(), "line": line, "file": mf.rel_path, "v2": True},
            )
            g.add_edge(fid, "HAS_ROUTE", rid, {"v2": True})
        if _NONCE_CHECK.search(text):
            nid = f"noncev2:{g.snapshot_id}:{mf.rel_path}"
            g.upsert_node(nid, "NonceGuardApprox", {"file": mf.rel_path, "v2": True})
            g.add_edge(fid, "HAS_NONCE_GUARD", nid, {"v2": True})
        if _CAP_CHECK.search(text):
            cid = f"capv2:{g.snapshot_id}:{mf.rel_path}"
            g.upsert_node(cid, "CapabilityCheck", {"file": mf.rel_path, "inferred": True, "v2": True})
            g.add_edge(fid, "HAS_CAP_CHECK", cid, {"v2": True})
        if _CRON.search(text):
            xid = f"cron:{g.snapshot_id}:{mf.rel_path}"
            g.upsert_node(xid, "SecuritySignal", {"signal": "CRON_PERSISTENCE", "file": mf.rel_path})
            g.add_edge(fid, "HAS_SECURITY_SIGNAL", xid, {})
        if _OPTION_WRITE.search(text):
            xid = f"opt:{g.snapshot_id}:{mf.rel_path}"
            g.upsert_node(xid, "SecuritySignal", {"signal": "OPTION_PERSISTENCE", "file": mf.rel_path})
            g.add_edge(fid, "HAS_SECURITY_SIGNAL", xid, {})
        if _UPLOAD.search(text):
            xid = f"upload:{g.snapshot_id}:{mf.rel_path}"
            g.upsert_node(xid, "SecuritySignal", {"signal": "UPLOAD_LIFECYCLE", "file": mf.rel_path})
            g.add_edge(fid, "HAS_SECURITY_SIGNAL", xid, {})
        if _MULTISITE.search(text):
            xid = f"ms:{g.snapshot_id}:{mf.rel_path}"
            g.upsert_node(xid, "SecuritySignal", {"signal": "MULTISITE_BOUNDARY", "file": mf.rel_path})
            g.add_edge(fid, "HAS_SECURITY_SIGNAL", xid, {})
