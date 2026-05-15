from __future__ import annotations

import re
from pathlib import Path

from hunter.graph.in_memory import InMemoryGraph
from hunter.models.core import RepoManifest

_SUPER = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\b")
_WPDB_QUERY = re.compile(r"\$wpdb\s*->\s*query\s*\(")
_ECHO = re.compile(r"\becho\s+")
_SANITIZER = re.compile(r"\b(esc_html|esc_attr|esc_url|wp_kses_post|sanitize_text_field)\s*\(")


def augment_taint(g: InMemoryGraph, manifest: RepoManifest) -> None:
    """Regex fallback taint when lift fact graph is disabled (HUNTER_REGEX_TAINT_FALLBACK_ENABLED)."""
    root = Path(manifest.root_path_norm)
    for mf in manifest.files:
        if mf.language_guess != "php":
            continue
        path = root / mf.rel_path
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        fid = f"file:{g.snapshot_id}:{mf.rel_path}"
        for m in _SUPER.finditer(text):
            var = f"_{m.group(1)}"
            line = text.count("\n", 0, m.start()) + 1
            sid = f"src:{g.snapshot_id}:{mf.rel_path}:{line}:{m.start()}"
            g.upsert_node(sid, "Source", {"kind": "HTTP_SUPERGLOBAL", "name": f"${var}", "line": line})
            g.add_edge(fid, "HAS_SOURCE", sid, {})
        for m in _WPDB_QUERY.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            kid = f"sink:{g.snapshot_id}:{mf.rel_path}:{line}:SQL"
            g.upsert_node(kid, "Sink", {"kind": "SQL", "line": line})
            g.add_edge(fid, "HAS_SINK", kid, {})
            # naive same-file flow edges from all sources in file to sink (pruned by rules)
            for m2 in _SUPER.finditer(text):
                line2 = text.count("\n", 0, m2.start()) + 1
                sid = f"src:{g.snapshot_id}:{mf.rel_path}:{line2}:{m2.start()}"
                if line2 <= line:
                    if _SANITIZER.search(text[m2.end() : m.start()]):
                        continue
                    g.add_edge(sid, "FLOWS_TO", kid, {"via": "same_file_ordering", "approx": True})
        for m in _ECHO.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            segment = text[m.end() : m.end() + 200]
            if _SUPER.search(segment) or "$" in segment[:80]:
                kid = f"sink:{g.snapshot_id}:{mf.rel_path}:{line}:XSS"
                g.upsert_node(kid, "Sink", {"kind": "HTML", "line": line})
                g.add_edge(fid, "HAS_SINK", kid, {})
                for m2 in _SUPER.finditer(text):
                    line2 = text.count("\n", 0, m2.start()) + 1
                    sid = f"src:{g.snapshot_id}:{mf.rel_path}:{line2}:{m2.start()}"
                    if line2 <= line:
                        if _SANITIZER.search(text[m2.end() : m.start()]):
                            continue
                        g.add_edge(sid, "FLOWS_TO", kid, {"via": "same_file_ordering", "approx": True})
