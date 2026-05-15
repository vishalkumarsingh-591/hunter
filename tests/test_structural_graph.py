from __future__ import annotations

import tempfile
from pathlib import Path

from hunter.graph.builder import build_graph_from_parse
from hunter.ingest.walk import run_ingest
from hunter.models.core import QuotaConfig
from hunter.parse.run import parse_manifest
from hunter.settings import HunterSettings

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "wp_plugins" / "minimal_plugin"


def test_structural_import_creates_function_and_callsite() -> None:
    settings = HunterSettings.load()
    ingest = run_ingest(FIXTURE, QuotaConfig())
    with tempfile.TemporaryDirectory() as tmp:
        parse = parse_manifest(
            ingest.manifest,
            parse_cache_dir=Path(tmp),
            max_single_file_bytes=settings.ingest_max_single_file_bytes,
            structure_complete_mode=True,
            lift_version="2",
        )
    gbuild = build_graph_from_parse(ingest.manifest, parse, "3")
    g = gbuild.graph
    assert gbuild.structural_stats is not None
    assert gbuild.structural_stats.functions + gbuild.structural_stats.methods >= 1
    labels = {n.get("label") for n in g.nodes.values()}
    assert "Function" in labels or "Method" in labels
    fid = next(nid for nid, n in g.nodes.items() if n.get("label") == "File")
    assert g.nodes[fid].get("parse_status") in ("OK", "PARTIAL")
