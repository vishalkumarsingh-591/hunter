from __future__ import annotations

import tempfile
from pathlib import Path

from hunter.analysis.rules import evaluators
from hunter.graph.builder import build_graph_from_parse
from hunter.graph.build_pipeline import build_analysis_graph
from hunter.graph.fact_security_augment import connect_same_file_flows
from hunter.graph.integrity import check_integrity
from hunter.graph.in_memory import InMemoryGraph
from hunter.graph.security_facts_catalog import augment_security_facts
from hunter.ingest.walk import run_ingest
from hunter.models.core import QuotaConfig
from hunter.models.findings import (
    CandidateFinding,
    ConfidenceRecord,
    EnrichedFinding,
    LocationAnchor,
    SkepticVerdict,
    StaticVerificationResult,
    Witness,
)
from hunter.parse.run import parse_manifest
from hunter.reporting.grouping import build_summary_groups, summary_group_key
from hunter.settings import HunterSettings
from hunter.verify_static.engine import verify_finding

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "wp_plugins" / "minimal_plugin"


def test_structural_unknown_target_integrity() -> None:
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
    ok, issues = check_integrity(gbuild.graph)
    assert ok, issues
    unknowns = [nid for nid, n in gbuild.graph.nodes.items() if n.get("label") == "UnknownTarget"]
    assert unknowns or gbuild.structural_stats.callsites == 0


def test_connect_same_file_one_flow_per_sink() -> None:
    g = InMemoryGraph(snapshot_id="snap", schema_version="3")
    fid = "file:snap:test.php"
    g.upsert_node(fid, "File", {"path": "test.php"})
    for i, line in enumerate((10, 20, 30), start=1):
        g.upsert_node(
            f"source:snap:test.php:{line}:0", "Source", {"line": line, "file": "test.php", "kind": "HTTP_SUPERGLOBAL"}
        )
        g.add_edge(fid, "HAS_SOURCE", f"source:snap:test.php:{line}:0", {})
    g.upsert_node("sink:snap:test.php:50:0", "Sink", {"line": 50, "file": "test.php", "kind": "FILE_INCLUDE"})
    g.add_edge(fid, "HAS_SINK", "sink:snap:test.php:50:0", {})
    added = connect_same_file_flows(g, max_edges_per_file=500)
    flows = [e for e in g.edges if e["rel"] == "FLOWS_TO"]
    assert added == 1
    assert len(flows) == 1
    assert flows[0]["src"] == "source:snap:test.php:30:0"


def test_include_ir_kind_emits_lfi_sink() -> None:
    from hunter.models.ir import FileParseArtifact, IRNode, ParseRunResult

    g = InMemoryGraph(snapshot_id="snap", schema_version="3")
    fid = "file:snap:dyn.php"
    g.upsert_node(fid, "File", {"path": "dyn.php"})
    art = FileParseArtifact(
        rel_path="dyn.php",
        language="php",
        ir_nodes=[
            IRNode(
                id="ir1",
                kind="include_expression",
                label="include $path",
                file_rel_path="dyn.php",
                start_byte=0,
                end_byte=14,
                start_line=8,
                end_line=8,
                start_col=0,
                end_col=14,
            ),
        ],
    )
    parse = ParseRunResult(parser_lock_hash="x", per_file={"dyn.php": art})
    stats = augment_security_facts(g, parse)
    sinks = [n for n in g.nodes.values() if n.get("label") == "Sink" and n.get("kind") == "FILE_INCLUDE"]
    assert stats.sinks >= 1
    assert sinks
    assert not sinks[0].get("static_arg")


def test_lfi_skips_static_include_sink() -> None:
    g = InMemoryGraph(snapshot_id="snap", schema_version="3")
    fid = "file:snap:safe.php"
    g.upsert_node(fid, "File", {"path": "safe.php"})
    g.upsert_node(
        "source:snap:safe.php:5:0",
        "Source",
        {"line": 5, "file": "safe.php", "name": "$_GET", "kind": "HTTP_SUPERGLOBAL"},
    )
    g.add_edge(fid, "HAS_SOURCE", "source:snap:safe.php:5:0", {})
    g.upsert_node(
        "sink:snap:safe.php:10:0",
        "Sink",
        {"line": 10, "file": "safe.php", "kind": "FILE_INCLUDE", "static_arg": True},
    )
    g.add_edge(fid, "HAS_SINK", "sink:snap:safe.php:10:0", {})
    connect_same_file_flows(g)
    findings = evaluators.eval_lfi_graph(g, _manifest_stub())
    assert not findings


def test_variable_include_produces_lfi_finding() -> None:
    g = InMemoryGraph(snapshot_id="snap", schema_version="3")
    fid = "file:snap:dyn.php"
    g.upsert_node(fid, "File", {"path": "dyn.php"})
    g.upsert_node(
        "source:snap:dyn.php:5:0", "Source", {"line": 5, "file": "dyn.php", "name": "$_GET", "kind": "HTTP_SUPERGLOBAL"}
    )
    g.add_edge(fid, "HAS_SOURCE", "source:snap:dyn.php:5:0", {})
    g.upsert_node(
        "sink:snap:dyn.php:10:0",
        "Sink",
        {"line": 10, "file": "dyn.php", "kind": "FILE_INCLUDE", "static_arg": False},
    )
    g.add_edge(fid, "HAS_SINK", "sink:snap:dyn.php:10:0", {})
    connect_same_file_flows(g)
    findings = evaluators.eval_lfi_graph(g, _manifest_stub())
    assert findings
    assert findings[0].rule_id == "RULE-LFI-001"


def test_summary_grouping_collapses_similar() -> None:
    def _enriched(rule_id: str, file_rel: str, sink_line: int, src_line: int, fid_suffix: str) -> EnrichedFinding:
        c = CandidateFinding(
            finding_id=f"FINDING|{rule_id}|x|y|{fid_suffix}",
            rule_id=rule_id,
            severity_band_static="MEDIUM",
            title_template_key="lfi.graph_flow",
            anchors=[
                LocationAnchor(
                    file_rel_path=file_rel,
                    start_line=src_line,
                    end_line=src_line,
                    start_col=0,
                    end_col=0,
                    start_byte=0,
                    end_byte=0,
                    ir_node_id="s",
                ),
                LocationAnchor(
                    file_rel_path=file_rel,
                    start_line=sink_line,
                    end_line=sink_line,
                    start_col=0,
                    end_col=0,
                    start_byte=0,
                    end_byte=0,
                    ir_node_id="k",
                ),
            ],
            witness=Witness(),
        )
        return EnrichedFinding(
            candidate=c,
            verification=StaticVerificationResult(status="CONFIRMED"),
            confidence=ConfidenceRecord(finding_id=c.finding_id, score=0.5, bucket="MEDIUM"),
            skeptic=SkepticVerdict(target_finding_id=c.finding_id, verdict="DOWNGRADE"),
        )

    items = [
        _enriched("RULE-LFI-001", "a.php", 47, 23, "a"),
        _enriched("RULE-LFI-001", "a.php", 47, 31, "b"),
        _enriched("RULE-XSS-001", "b.php", 10, 5, "c"),
    ]
    assert summary_group_key(items[0]) == summary_group_key(items[1])
    groups = build_summary_groups(items)
    assert len(groups) == 2
    lfi = next(g for g in groups if g.rule_id == "RULE-LFI-001")
    assert lfi.count == 2


def test_approx_flow_verification_inconclusive() -> None:
    c = CandidateFinding(
        finding_id="f1",
        rule_id="RULE-LFI-001",
        severity_band_static="MEDIUM",
        title_template_key="lfi.graph_flow",
        anchors=[
            LocationAnchor(
                file_rel_path="x.php",
                start_line=1,
                end_line=1,
                start_col=0,
                end_col=0,
                start_byte=0,
                end_byte=0,
                ir_node_id="s",
            ),
        ],
        witness=Witness(
            path_edges=["a|FLOWS_TO|b"],
            constraint_summary={"approximate_flow": True},
            semantic_trace=["graph:source:a"],
        ),
    )
    ver = verify_finding(c)
    assert ver.status == "INCONCLUSIVE"


def _manifest_stub():
    from hunter.models.core import RepoManifest, RepoManifestFile

    return RepoManifest(
        root_path_norm=str(FIXTURE),
        manifest_sha256="0" * 64,
        files=(
            RepoManifestFile(
                rel_path="safe.php",
                abs_path_norm=str(FIXTURE / "safe.php"),
                sha256="0" * 64,
                size=1,
                language_guess="php",
            ),
        ),
    )
