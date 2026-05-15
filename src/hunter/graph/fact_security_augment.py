"""Emit security-relevant fact nodes from parse IR (deterministic, no regex file scans)."""

from __future__ import annotations

import re

from hunter.graph.in_memory import InMemoryGraph
from hunter.models.ir import FileParseArtifact, IRNode, ParseRunResult

_SUPER_LABEL = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b")
_WPDB_QUERY = re.compile(r"\$wpdb\s*->\s*query\s*\(", re.IGNORECASE)
_WPDB_PREPARE = re.compile(r"\$wpdb\s*->\s*prepare\s*\(", re.IGNORECASE)
_ECHO = re.compile(r"\becho\b")
_SANITIZER = re.compile(
    r"\b(esc_html|esc_attr|esc_url|esc_js|esc_textarea|wp_kses_post|sanitize_text_field|sanitize_email|absint)\s*\(",
    re.IGNORECASE,
)

# Heuristic patterns for graph-backed rules (evaluators must not re-read files)
_RE_REQUEST_OPTION = re.compile(r"\$_REQUEST\s*\[\s*['\"]option['\"]\s*\]")
_RE_GET_METHOD = re.compile(
    r"['\"]GET['\"]\s*===\s*\$_SERVER\s*\[\s*['\"]REQUEST_METHOD['\"]\s*\]", re.IGNORECASE
)
_RE_POST_METHOD = re.compile(
    r"['\"]POST['\"]\s*===\s*\$_SERVER\s*\[\s*['\"]REQUEST_METHOD['\"]\s*\]", re.IGNORECASE
)
_RE_NONCE_ON_GET = re.compile(r"\$_GET\s*\[\s*['\"]_wpnonce['\"]\s*\].*?wp_verify_nonce\s*\(", re.DOTALL)
_RE_NONCE_ANY = re.compile(r"\bwp_verify_nonce\s*\(|\bcheck_admin_referer\s*\(", re.IGNORECASE)

_URL_SANITIZERS = frozenset({"esc_url", "esc_url_raw", "sanitize_file_name", "sanitize_text_field"})


def _context_for_sanitizer(name: str) -> str:
    n = name.lower()
    if n.startswith("esc_") or n == "wp_kses_post":
        return "HTML"
    if n in _URL_SANITIZERS:
        return "URL"
    if n in ("sanitize_text_field", "sanitize_email", "absint"):
        return "GENERIC"
    return "UNKNOWN"


def _sanitizer_blocks_sink(sn: dict, sk: dict) -> bool:
    skind = str(sk.get("kind", ""))
    sctx = str(sn.get("context", ""))
    skind_s = str(sn.get("kind", ""))
    sname = str(sn.get("name", "")).lower()
    if skind == "SQL" and (sctx == "SQL" or skind_s == "SQL_PREPARE"):
        return True
    if skind == "HTML" and sctx == "HTML":
        return True
    if skind in ("REDIRECT", "FILE_INCLUDE", "REMOTE_READ", "UPLOAD") and (
        sctx == "URL" or sname in _URL_SANITIZERS
    ):
        return True
    if skind == "HTTP_CLIENT" and sctx in ("URL", "GENERIC"):
        return True
    return False


_HAS_REL = {"Source": "HAS_SOURCE", "Sink": "HAS_SINK", "Sanitizer": "HAS_SANITIZER"}


def _emit_from_ir(
    g: InMemoryGraph,
    fid: str,
    sid: str,
    ir: IRNode,
    *,
    label: str,
    props: dict,
) -> str:
    nid = f"{label.lower()}:{sid}:{ir.file_rel_path}:{ir.start_line}:{ir.start_byte}"
    g.upsert_node(nid, label, {**props, "line": ir.start_line, "file": ir.file_rel_path, "ir_node_id": ir.id})
    g.add_edge(fid, _HAS_REL[label], nid, {})
    ir_gid = f"ir:{sid}:{ir.id}"
    if ir_gid in g.nodes:
        g.add_edge(nid, "ANCHORED_AT", ir_gid, {})
    return nid


def augment_fact_security_from_parse(g: InMemoryGraph, parse: ParseRunResult) -> None:
    """Deprecated: use graph.security_facts_catalog.augment_security_facts via build_pipeline."""
    from hunter.graph.security_facts_catalog import augment_security_facts

    augment_security_facts(g, parse)


def connect_same_file_flows(g: InMemoryGraph, *, max_edges_per_file: int = 500) -> int:
    """Connect each sink to the nearest source above it in the same file (no full Cartesian product)."""
    sid = g.snapshot_id
    added = 0
    by_file: dict[str, list[str]] = {}
    for nid, n in g.nodes.items():
        if n.get("label") not in {"Source", "Sink", "Sanitizer"}:
            continue
        f = str(n.get("file", ""))
        if f:
            by_file.setdefault(f, []).append(nid)

    existing: set[tuple[str, str]] = {
        (e["src"], e["dst"]) for e in g.edges if e["rel"] == "FLOWS_TO"
    }

    for file_rel, nids in sorted(by_file.items()):
        fid = f"file:{sid}:{file_rel}"
        sources = sorted(
            (nid for nid in nids if g.nodes[nid].get("label") == "Source"),
            key=lambda x: int(g.nodes[x].get("line", 0)),
        )
        sinks = sorted(
            (nid for nid in nids if g.nodes[nid].get("label") == "Sink"),
            key=lambda x: int(g.nodes[x].get("line", 0)),
        )
        sanitizers = [nid for nid in nids if g.nodes[nid].get("label") == "Sanitizer"]
        file_added = 0
        for kid in sinks:
            if file_added >= max_edges_per_file:
                break
            kline = int(g.nodes[kid].get("line", 0))
            skind = str(g.nodes[kid].get("kind", ""))
            best_src: str | None = None
            best_dist = -1
            for src in sources:
                sline = int(g.nodes[src].get("line", 0))
                if sline > kline:
                    continue
                dist = kline - sline
                if best_src is None or dist < best_dist:
                    best_src = src
                    best_dist = dist
            if best_src is None:
                continue
            if (best_src, kid) in existing:
                continue
            blocked = False
            for san in sanitizers:
                sn = g.nodes[san]
                sline_s = int(sn.get("line", 0))
                if not (int(g.nodes[best_src].get("line", 0)) < sline_s <= kline):
                    continue
                if _sanitizer_blocks_sink(sn, g.nodes[kid]):
                    blocked = True
                    g.add_edge(san, "PROTECTS", kid, {"context": skind})
                    break
            if blocked:
                continue
            g.add_edge(
                best_src,
                "FLOWS_TO",
                kid,
                {"via": "same_file_ordering", "approx": True, "from_lift": True},
            )
            existing.add((best_src, kid))
            file_added += 1
            added += 1
    return added


def _augment_file(
    g: InMemoryGraph,
    fid: str,
    sid: str,
    rel_path: str,
    art: FileParseArtifact,
) -> None:
    file_text = "\n".join(n.label for n in art.ir_nodes)
    # Heuristic patterns at file granularity (for nonce rule without evaluator file reads)
    if _RE_REQUEST_OPTION.search(file_text) and _RE_GET_METHOD.search(file_text) and _RE_NONCE_ANY.search(file_text):
        m = _RE_NONCE_ON_GET.search(file_text)
        if m and not (_RE_POST_METHOD.search(file_text) and "check_admin_referer" in file_text):
            line = file_text.count("\n", 0, m.start()) + 1
            pid = f"pattern:{sid}:{rel_path}:NONCE_GET_ONLY:{line}"
            g.upsert_node(
                pid,
                "HeuristicPattern",
                {
                    "pattern": "NONCE_GET_ONLY",
                    "line": line,
                    "file": rel_path,
                    "detail": "nonce_verification_gated_on_get_only",
                },
            )
            g.add_edge(fid, "HAS_PATTERN", pid, {})
    _augment_file_ir_nodes(g, fid, sid, rel_path, art)


def _augment_file_ir_nodes(
    g: InMemoryGraph,
    fid: str,
    sid: str,
    rel_path: str,
    art: FileParseArtifact,
) -> None:
    for ir in art.ir_nodes:
        text = ir.label
        if _SUPER_LABEL.search(text):
            m = _SUPER_LABEL.search(text)
            var = m.group(1) if m else "REQUEST"
            _emit_from_ir(
                g,
                fid,
                sid,
                ir,
                label="Source",
                props={"kind": "HTTP_SUPERGLOBAL", "name": f"$_{var}", "context": "HTTP_INPUT"},
            )
        if _WPDB_QUERY.search(text):
            _emit_from_ir(
                g,
                fid,
                sid,
                ir,
                label="Sink",
                props={"kind": "SQL", "context": "SQL", "api": "wpdb_query"},
            )
        if _ECHO.search(text):
            _emit_from_ir(
                g,
                fid,
                sid,
                ir,
                label="Sink",
                props={"kind": "HTML", "context": "HTML", "api": "echo"},
            )
        if _WPDB_PREPARE.search(text):
            _emit_from_ir(
                g,
                fid,
                sid,
                ir,
                label="Sanitizer",
                props={"kind": "SQL_PREPARE", "name": "wpdb_prepare", "context": "SQL"},
            )
        for sm in _SANITIZER.finditer(text):
            name = sm.group(1)
            _emit_from_ir(
                g,
                fid,
                sid,
                ir,
                label="Sanitizer",
                props={"kind": "SANITIZE", "name": name, "context": _context_for_sanitizer(name)},
            )
