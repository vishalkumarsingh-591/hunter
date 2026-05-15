from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from hunter.graph.in_memory import InMemoryGraph
from hunter.models.core import RepoManifest

_UNSERIALIZE = re.compile(r"\bunserialize\s*\(")
_MAGIC_METHOD = re.compile(r"function\s+(__wakeup|__destruct|__toString|__call)\s*\(")
_DANGEROUS_SINK = re.compile(r"\b(eval|assert|shell_exec|system|passthru|exec)\s*\(")


@dataclass
class SecurityAdvancedResult:
    unserialize_sites: int = 0
    gadget_candidates: int = 0
    reachable_sink_candidates: int = 0
    variants: list[str] = field(default_factory=list)


def augment_security_advanced(g: InMemoryGraph, manifest: RepoManifest) -> SecurityAdvancedResult:
    root = Path(manifest.root_path_norm)
    result = SecurityAdvancedResult()
    for mf in manifest.files:
        if mf.language_guess != "php":
            continue
        p = root / mf.rel_path
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        fid = f"file:{g.snapshot_id}:{mf.rel_path}"
        for m in _UNSERIALIZE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            result.unserialize_sites += 1
            nid = f"objinj:{g.snapshot_id}:{mf.rel_path}:{line}"
            g.upsert_node(
                nid,
                "SecuritySignal",
                {
                    "signal": "OBJECT_INJECTION_ENTRYPOINT",
                    "line": line,
                    "file": mf.rel_path,
                    "category": "OBJECT_INJECTION",
                },
            )
            g.add_edge(fid, "HAS_SECURITY_SIGNAL", nid, {})
        mm = list(_MAGIC_METHOD.finditer(text))
        if mm:
            result.gadget_candidates += len(mm)
            for m in mm:
                line = text.count("\n", 0, m.start()) + 1
                gid = f"gadget:{g.snapshot_id}:{mf.rel_path}:{m.group(1)}:{line}"
                g.upsert_node(
                    gid,
                    "SecuritySignal",
                    {
                        "signal": "POP_GADGET_CANDIDATE",
                        "magic_method": m.group(1),
                        "line": line,
                        "file": mf.rel_path,
                        "gadget_score": 0.2,
                    },
                )
                g.add_edge(fid, "HAS_SECURITY_SIGNAL", gid, {})
        for m in _DANGEROUS_SINK.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            result.reachable_sink_candidates += 1
            sid = f"dangsink:{g.snapshot_id}:{mf.rel_path}:{line}"
            g.upsert_node(
                sid,
                "SecuritySignal",
                {
                    "signal": "REACHABLE_DANGEROUS_SINK_CANDIDATE",
                    "line": line,
                    "file": mf.rel_path,
                    "sink": m.group(1),
                },
            )
            g.add_edge(fid, "HAS_SECURITY_SIGNAL", sid, {})
        if result.unserialize_sites and mm:
            result.variants.append(f"{mf.rel_path}:object-injection-pop-chain")
    return result
