"""Central catalog of security sources/sinks/signals from graph IR and callsites."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hunter.graph.fact_security_augment import connect_same_file_flows
from hunter.graph.in_memory import InMemoryGraph
from hunter.models.ir import FileParseArtifact, ParseRunResult

_HAS_REL = {"Source": "HAS_SOURCE", "Sink": "HAS_SINK", "Sanitizer": "HAS_SANITIZER"}

_INCLUDE_IR_KINDS = frozenset(
    {
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
    }
)

_STATIC_PATH_MARKERS = re.compile(
    r"__DIR__|ABSPATH|plugin_dir_path|dirname\s*\(\s*__FILE__",
    re.IGNORECASE,
)
_STATIC_INCLUDE_ARG = re.compile(
    r"\b(include|require)(_once)?\s*(\(\s*['\"]|['\"]\s*\)|\s+['\"])",
    re.IGNORECASE,
)
_INCLUDE_IN_LABEL = re.compile(
    r"(?<![A-Za-z0-9_])(include|require)(_once)?(\s*\(|\s+)",
    re.IGNORECASE,
)

# (label, pattern, props) — all patterns run on IR labels and callsite previews
_PATTERNS: list[tuple[str, str, dict]] = [
    ("Source", r"\$_(GET|POST|REQUEST)\b", {"kind": "HTTP_SUPERGLOBAL", "context": "HTTP_INPUT"}),
    ("Source", r"\$_(COOKIE|SERVER)\b", {"kind": "HTTP_SUPERGLOBAL", "context": "HTTP_INPUT"}),
    ("Sink", r"\$wpdb\s*->\s*query\s*\(", {"kind": "SQL", "context": "SQL", "api": "wpdb_query"}),
    ("Sink", r"\$wpdb\s*->\s*(get_results|get_var|get_row)\s*\(", {"kind": "SQL", "context": "SQL"}),
    ("Sink", r"\becho\s+", {"kind": "HTML", "context": "HTML", "api": "echo"}),
    ("Sink", r"\bwp_redirect\s*\(", {"kind": "REDIRECT", "context": "URL", "api": "wp_redirect"}),
    ("Sink", r"\b(header|wp_safe_redirect)\s*\(", {"kind": "REDIRECT", "context": "URL"}),
    ("Sink", r"(?<![A-Za-z0-9_])(include|require)(_once)?(\s*\(|\s+)", {"kind": "FILE_INCLUDE", "context": "FILE"}),
    ("Sink", r"\b(file_get_contents|readfile|fopen)\s*\(", {"kind": "REMOTE_READ", "context": "FILE"}),
    ("Sink", r"\b(eval|assert|shell_exec|system|passthru|exec)\s*\(", {"kind": "CODE_EXEC", "context": "SHELL"}),
    ("Sink", r"\b(move_uploaded_file|wp_handle_upload)\s*\(", {"kind": "UPLOAD", "context": "FILE"}),
    ("Sink", r"\bwp_remote_(get|post|request)\s*\(", {"kind": "HTTP_CLIENT", "context": "SSRF"}),
    ("Sink", r"\bfputcsv\s*\(", {"kind": "CSV_OUTPUT", "context": "CSV"}),
    ("Sink", r"\bunserialize\s*\(", {"kind": "OBJECT_INJECTION", "context": "DESERIALIZE"}),
    ("Sanitizer", r"\$wpdb\s*->\s*prepare\s*\(", {"kind": "SQL_PREPARE", "name": "wpdb_prepare", "context": "SQL"}),
    (
        "Sanitizer",
        r"\b(esc_html|esc_attr|esc_url|esc_js|wp_kses_post|sanitize_text_field|esc_url_raw|sanitize_file_name)\s*\(",
        {"kind": "SANITIZE", "context": "HTML"},
    ),
]

_HEURISTIC_PATTERNS = [
    (
        "NONCE_GET_ONLY",
        r"\$_REQUEST\s*\[\s*['\"]option['\"]\s*\]",
        r"['\"]GET['\"]\s*===\s*\$_SERVER",
        r"wp_verify_nonce",
    ),
]


@dataclass
class SecurityFactsStats:
    sources: int = 0
    sinks: int = 0
    sanitizers: int = 0


def _sink_props(text: str, base: dict) -> dict:
    p = dict(base)
    kind = p.get("kind", "")
    if kind == "FILE_INCLUDE":
        if _STATIC_INCLUDE_ARG.search(text) or _STATIC_PATH_MARKERS.search(text):
            p["static_arg"] = True
    elif kind == "REMOTE_READ" and _STATIC_PATH_MARKERS.search(text):
        p["static_path_likely"] = True
    return p


def _emit(
    g: InMemoryGraph,
    fid: str,
    sid: str,
    file_rel: str,
    line: int,
    byte_off: int,
    label: str,
    props: dict,
    *,
    seen: set[tuple[str, str, int, str]],
) -> str | None:
    kind_key = props.get("kind", label) if label == "Sink" else label
    dedupe_key = (file_rel, label, line, str(kind_key))
    if dedupe_key in seen:
        return None
    seen.add(dedupe_key)
    nid = f"{label.lower()}:{sid}:{file_rel}:{line}:{byte_off}"
    g.upsert_node(nid, label, {**props, "line": line, "file": file_rel})
    g.add_edge(fid, _HAS_REL[label], nid, {})
    return nid


def _collect_texts(
    g: InMemoryGraph,
    sid: str,
    file_rel: str,
    art: FileParseArtifact,
) -> list[tuple[str, int, int]]:
    texts: list[tuple[str, int, int]] = []
    for ir in art.ir_nodes:
        texts.append((ir.label, ir.start_line, ir.start_byte))
    fid = f"file:{sid}:{file_rel}"
    for e in g.edges:
        if e["src"] == fid and e["rel"] == "CONTAINS_IR":
            irn = g.nodes.get(e["dst"], {})
            preview = str(irn.get("label_preview", ""))
            if preview and not any(preview == t[0] and irn.get("start_line") == t[1] for t in texts):
                texts.append((preview, int(irn.get("start_line", 0)), int(irn.get("start_byte", 0))))
    for nid, n in g.nodes.items():
        if n.get("file") != file_rel:
            continue
        if str(nid).startswith(f"callsite:{sid}:"):
            preview = str(n.get("label_preview", ""))
            if preview:
                texts.append((preview, int(n.get("line", 0)), 0))
    return texts


def _emit_include_ir_sinks(
    g: InMemoryGraph,
    fid: str,
    sid: str,
    file_rel: str,
    art: FileParseArtifact,
    seen: set[tuple[str, str, int, str]],
    stats: SecurityFactsStats,
) -> None:
    for ir in art.ir_nodes:
        if ir.kind not in _INCLUDE_IR_KINDS:
            continue
        props = _sink_props(ir.label, {"kind": "FILE_INCLUDE", "context": "FILE", "ir_kind": ir.kind})
        if _emit(g, fid, sid, file_rel, ir.start_line, ir.start_byte, "Sink", props, seen=seen):
            stats.sinks += 1


def augment_security_facts(
    g: InMemoryGraph,
    parse: ParseRunResult,
    *,
    max_same_file_flow_edges_per_file: int = 500,
) -> SecurityFactsStats:
    sid = g.snapshot_id
    stats = SecurityFactsStats()
    compiled = [(lab, re.compile(pat, re.I if lab != "Source" else 0), props) for lab, pat, props in _PATTERNS]

    for rel_path, art in sorted(parse.per_file.items()):
        if art.language != "php":
            continue
        fid = f"file:{sid}:{rel_path}"
        if fid not in g.nodes:
            continue
        seen: set[tuple[str, str, int, str]] = set()
        texts = _collect_texts(g, sid, rel_path, art)

        file_blob = "\n".join(t[0] for t in texts)
        for pat_name, req1, req2, req3 in _HEURISTIC_PATTERNS:
            if re.search(req1, file_blob) and re.search(req2, file_blob, re.I) and re.search(req3, file_blob, re.I):
                pid = f"pattern:{sid}:{rel_path}:{pat_name}"
                g.upsert_node(pid, "HeuristicPattern", {"pattern": pat_name, "file": rel_path, "line": 1})
                g.add_edge(fid, "HAS_PATTERN", pid, {})

        _emit_include_ir_sinks(g, fid, sid, rel_path, art, seen, stats)

        for text, line, byte_off in texts:
            for lab, rx, props in compiled:
                if lab == "Sink" and props.get("kind") == "FILE_INCLUDE":
                    if not _INCLUDE_IN_LABEL.search(text):
                        continue
                elif not rx.search(text):
                    continue
                p = dict(props)
                if lab == "Source":
                    m = rx.search(text)
                    p = {**props, "name": f"$_{m.group(1)}" if m else "$_REQUEST"}
                elif lab == "Sink":
                    p = _sink_props(text, props)
                if lab == "Sanitizer" and "name" not in p:
                    m = re.search(r"\b([a-z_]+)\s*\(", text, re.I)
                    if m:
                        p["name"] = m.group(1)
                if _emit(g, fid, sid, rel_path, line, byte_off, lab, p, seen=seen):
                    if lab == "Source":
                        stats.sources += 1
                    elif lab == "Sink":
                        stats.sinks += 1
                    else:
                        stats.sanitizers += 1

    connect_same_file_flows(g, max_edges_per_file=max_same_file_flow_edges_per_file)
    return stats
