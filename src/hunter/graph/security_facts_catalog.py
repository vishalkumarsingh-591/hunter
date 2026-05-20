"""Central catalog of security sources/sinks/signals from graph IR and callsites."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

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

_CATALOGS_DIR = Path(__file__).resolve().parents[1] / "analysis" / "rules" / "catalogs"

_URL_SANITIZERS = frozenset({"esc_url", "esc_url_raw", "sanitize_file_name", "sanitize_text_field"})


class CatalogPattern(BaseModel):
    label: str
    pattern: str
    props: dict[str, Any] = Field(default_factory=dict)


class HeuristicPatternSpec(BaseModel):
    name: str
    requirements: list[str]


class SecurityCatalog(BaseModel):
    catalog_id: str
    version: str = "1"
    languages: list[str] = Field(default_factory=lambda: ["php"])
    patterns: list[CatalogPattern] = Field(default_factory=list)
    heuristic_patterns: list[HeuristicPatternSpec] = Field(default_factory=list)


def catalogs_dir() -> Path:
    return _CATALOGS_DIR


def load_catalog(catalog_id: str) -> SecurityCatalog:
    path = _CATALOGS_DIR / f"{catalog_id}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"security catalog not found: {catalog_id}")
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return SecurityCatalog.model_validate(raw)


def merge_catalogs(catalog_ids: list[str]) -> tuple[SecurityCatalog, list[tuple[str, re.Pattern[str], dict]]]:
    """Merge catalogs; later ids override same (label, kind) patterns."""
    merged_patterns: list[CatalogPattern] = []
    merged_heuristics: list[HeuristicPatternSpec] = []
    seen_kind: set[tuple[str, str, str]] = set()
    langs: list[str] = []
    versions: list[str] = []
    for cid in catalog_ids:
        cat = load_catalog(cid)
        versions.append(cat.version)
        for lang in cat.languages:
            if lang not in langs:
                langs.append(lang)
        for p in cat.patterns:
            kind = str(p.props.get("kind", p.label))
            api = str(p.props.get("api", p.pattern))
            key = (p.label, kind, api)
            if key in seen_kind:
                continue
            seen_kind.add(key)
            merged_patterns.append(p)
        for h in cat.heuristic_patterns:
            if not any(x.name == h.name for x in merged_heuristics):
                merged_heuristics.append(h)
    merged = SecurityCatalog(
        catalog_id="|".join(catalog_ids),
        version=".".join(versions),
        languages=langs or ["php"],
        patterns=merged_patterns,
        heuristic_patterns=merged_heuristics,
    )
    compiled: list[tuple[str, re.Pattern[str], dict]] = []
    for p in merged.patterns:
        flags = re.I if p.label != "Source" else 0
        compiled.append((p.label, re.compile(p.pattern, flags), dict(p.props)))
    return merged, compiled


def catalog_hash(catalog_ids: list[str]) -> str:
    cats = [load_catalog(cid).model_dump(mode="json") for cid in catalog_ids]
    canonical = json.dumps(cats, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclass
class SecurityFactsStats:
    sources: int = 0
    sinks: int = 0
    sanitizers: int = 0


def _context_for_sanitizer(name: str) -> str:
    n = name.lower()
    if n.startswith("esc_") or n == "wp_kses_post":
        return "HTML"
    if n in _URL_SANITIZERS:
        return "URL"
    if n in ("sanitize_text_field", "sanitize_email", "absint", "htmlspecialchars", "filter_var", "intval"):
        return "GENERIC"
    return "UNKNOWN"


def _sanitizer_blocks_sink(sn: dict, sk: dict) -> bool:
    skind = str(sk.get("kind", ""))
    sctx = str(sn.get("context", ""))
    skind_s = str(sn.get("kind", ""))
    sname = str(sn.get("name", "")).lower()
    if skind == "SQL" and (sctx == "SQL" or skind_s == "SQL_PREPARE"):
        return True
    if skind == "HTML" and sctx in ("HTML", "GENERIC"):
        return True
    if skind in ("REDIRECT", "FILE_INCLUDE", "REMOTE_READ", "UPLOAD", "FILE_WRITE") and (
        sctx in ("URL", "GENERIC") or sname in _URL_SANITIZERS
    ):
        return True
    if skind == "HTTP_CLIENT" and sctx in ("URL", "GENERIC"):
        return True
    return False


def connect_same_file_flows(g: InMemoryGraph, *, max_edges_per_file: int = 500) -> int:
    """Connect each sink to the nearest source above it in the same file."""
    added = 0
    by_file: dict[str, list[str]] = {}
    for nid, n in g.nodes.items():
        if n.get("label") not in {"Source", "Sink", "Sanitizer"}:
            continue
        f = str(n.get("file", ""))
        if f:
            by_file.setdefault(f, []).append(nid)

    existing: set[tuple[str, str]] = {(e["src"], e["dst"]) for e in g.edges if e["rel"] == "FLOWS_TO"}

    for file_rel, nids in sorted(by_file.items()):
        sources = sorted(
            (nid for nid in nids if g.nodes[nid].get("label") == "Source"),
            key=lambda x: int(g.nodes[x].get("line", 0)),
        )
        sinks = sorted(
            (nid for nid in nids if g.nodes[nid].get("label") == "Sink"),
            key=lambda x: int(g.nodes[x].get("line", 0)),
        )
        sanitizers = sorted(
            (nid for nid in nids if g.nodes[nid].get("label") == "Sanitizer"),
            key=lambda x: int(g.nodes[x].get("line", 0)),
        )
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


def _sink_props(text: str, base: dict) -> dict:
    p = dict(base)
    kind = p.get("kind", "")
    if kind == "FILE_INCLUDE":
        if _STATIC_INCLUDE_ARG.search(text) or _STATIC_PATH_MARKERS.search(text):
            p["static_arg"] = True
    elif kind in ("REMOTE_READ", "FILE_WRITE") and _STATIC_PATH_MARKERS.search(text):
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
    texts.sort(key=lambda t: (t[1], t[2], t[0]))
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


@dataclass
class FileSecurityShard:
    nodes: dict[str, dict[str, Any]]
    edges: list[tuple[str, str, str, dict[str, Any] | None]]
    stats: SecurityFactsStats


def _emit_shard(
    nodes: dict[str, dict[str, Any]],
    edges: list[tuple[str, str, str, dict[str, Any] | None]],
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
    nodes[nid] = {"id": nid, "label": label, **props, "line": line, "file": file_rel}
    edges.append((fid, _HAS_REL[label], nid, {}))
    return nid


def _collect_texts_shard(
    sid: str,
    file_rel: str,
    art: FileParseArtifact,
    structural_nodes: dict[str, dict[str, Any]],
) -> list[tuple[str, int, int]]:
    texts: list[tuple[str, int, int]] = []
    for ir in art.ir_nodes:
        texts.append((ir.label, ir.start_line, ir.start_byte))
    for nid, n in structural_nodes.items():
        if n.get("file") != file_rel:
            continue
        if str(nid).startswith(f"callsite:{sid}:"):
            preview = str(n.get("label_preview", ""))
            if preview:
                texts.append((preview, int(n.get("line", 0)), 0))
    texts.sort(key=lambda t: (t[1], t[2], t[0]))
    return texts


def augment_security_facts_file(
    sid: str,
    rel_path: str,
    art: FileParseArtifact,
    structural_nodes: dict[str, dict[str, Any]],
    structural_edges: list[tuple[str, str, str, dict[str, Any] | None]],
    *,
    compiled: list[tuple[str, re.Pattern[str], dict]],
    heuristics: list[HeuristicPatternSpec],
) -> FileSecurityShard:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[tuple[str, str, str, dict[str, Any] | None]] = []
    stats = SecurityFactsStats()
    if art.language != "php":
        return FileSecurityShard(nodes=nodes, edges=edges, stats=stats)

    fid = f"file:{sid}:{rel_path}"
    seen: set[tuple[str, str, int, str]] = set()
    texts = _collect_texts_shard(sid, rel_path, art, structural_nodes)

    file_blob = "\n".join(t[0] for t in texts)
    for h in heuristics:
        if all(re.search(req, file_blob, re.I if "GET" in req else 0) for req in h.requirements):
            pid = f"pattern:{sid}:{rel_path}:{h.name}"
            nodes[pid] = {"id": pid, "label": "HeuristicPattern", "pattern": h.name, "file": rel_path, "line": 1}
            edges.append((fid, "HAS_PATTERN", pid, {}))

    for ir in art.ir_nodes:
        if ir.kind not in _INCLUDE_IR_KINDS:
            continue
        props = _sink_props(ir.label, {"kind": "FILE_INCLUDE", "context": "FILE", "ir_kind": ir.kind})
        if _emit_shard(nodes, edges, fid, sid, rel_path, ir.start_line, ir.start_byte, "Sink", props, seen=seen):
            stats.sinks += 1

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
                if m and m.lastindex:
                    p = {**props, "name": f"$_{m.group(1)}"}
                elif "name" in props:
                    p = dict(props)
                else:
                    p = {**props, "name": "$_REQUEST"}
            elif lab == "Sink":
                p = _sink_props(text, props)
            if lab == "Sanitizer" and "name" not in p:
                m = re.search(r"\b([a-z_]+)\s*\(", text, re.I)
                if m:
                    p["name"] = m.group(1)
                    if "context" not in p or p.get("context") == "HTML":
                        p["context"] = _context_for_sanitizer(m.group(1))
            if _emit_shard(nodes, edges, fid, sid, rel_path, line, byte_off, lab, p, seen=seen):
                if lab == "Source":
                    stats.sources += 1
                elif lab == "Sink":
                    stats.sinks += 1
                else:
                    stats.sanitizers += 1

    return FileSecurityShard(nodes=nodes, edges=edges, stats=stats)


def augment_security_facts(
    g: InMemoryGraph,
    parse: ParseRunResult,
    *,
    catalog_ids: list[str] | None = None,
    max_same_file_flow_edges_per_file: int = 500,
) -> SecurityFactsStats:
    ids = catalog_ids or ["generic-php-v1"]
    _merged, compiled = merge_catalogs(ids)
    heuristics = _merged.heuristic_patterns

    sid = g.snapshot_id
    stats = SecurityFactsStats()

    for rel_path, art in sorted(parse.per_file.items()):
        if art.language != "php":
            continue
        fid = f"file:{sid}:{rel_path}"
        if fid not in g.nodes:
            continue
        seen: set[tuple[str, str, int, str]] = set()
        texts = _collect_texts(g, sid, rel_path, art)

        file_blob = "\n".join(t[0] for t in texts)
        for h in heuristics:
            if all(re.search(req, file_blob, re.I if "GET" in req else 0) for req in h.requirements):
                pid = f"pattern:{sid}:{rel_path}:{h.name}"
                g.upsert_node(pid, "HeuristicPattern", {"pattern": h.name, "file": rel_path, "line": 1})
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
                    if m and m.lastindex:
                        p = {**props, "name": f"$_{m.group(1)}"}
                    elif "name" in props:
                        p = dict(props)
                    else:
                        p = {**props, "name": "$_REQUEST"}
                elif lab == "Sink":
                    p = _sink_props(text, props)
                if lab == "Sanitizer" and "name" not in p:
                    m = re.search(r"\b([a-z_]+)\s*\(", text, re.I)
                    if m:
                        p["name"] = m.group(1)
                        if "context" not in p or p.get("context") == "HTML":
                            p["context"] = _context_for_sanitizer(m.group(1))
                if _emit(g, fid, sid, rel_path, line, byte_off, lab, p, seen=seen):
                    if lab == "Source":
                        stats.sources += 1
                    elif lab == "Sink":
                        stats.sinks += 1
                    else:
                        stats.sanitizers += 1

    connect_same_file_flows(g, max_edges_per_file=max_same_file_flow_edges_per_file)
    return stats
