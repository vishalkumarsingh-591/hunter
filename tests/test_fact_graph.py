from __future__ import annotations

import ast
import inspect
import tempfile
from pathlib import Path

from hunter.analysis.rules import evaluators
from hunter.analysis.rules.loader import RulePack, load_rule_pack, schema_meets_minimum
from hunter.graph.in_memory import InMemoryGraph


def test_rule_pack_schema_versions() -> None:
    pack = load_rule_pack(Path(__file__).resolve().parents[1] / "src" / "hunter" / "analysis" / "rules" / "packs" / "default.yaml")
    assert pack.version == "3"
    for rule in pack.rules:
        assert rule.min_graph_schema_version in ("3", "4", "5")


def test_schema_meets_minimum() -> None:
    assert schema_meets_minimum("2", "1")
    assert schema_meets_minimum("2", "2")
    assert not schema_meets_minimum("1", "2")


def test_evaluators_do_not_open_files() -> None:
    """Evaluators must query the graph only (no filesystem reads of plugin code)."""
    for name, fn in evaluators.EVALUATORS.items():
        src = inspect.getsource(fn)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "open":
                    raise AssertionError(f"evaluator {name} uses open() — migrate to graph facts")
                if isinstance(func, ast.Attribute) and func.attr in ("read_text", "read_bytes"):
                    raise AssertionError(f"evaluator {name} reads files directly — migrate to graph facts")


def test_analysis_modules_avoid_plugin_read_text() -> None:
    """Phase 5: analysis package must not read plugin source (graph is truth at rule time)."""
    root = Path(__file__).resolve().parents[1] / "src" / "hunter" / "analysis"
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if "resolver.py" in path.name and "resolver_graph" not in path.name:
            text = path.read_text(encoding="utf-8")
            if "read_text" in text and "manifest" in text:
                offenders.append(str(path.relative_to(root)))
    assert not offenders, f"analysis still reads plugin files: {offenders}"


def test_sqli_graph_evaluator_on_minimal_fixture() -> None:
    from hunter.graph.builder import build_graph_from_parse
    from hunter.graph.build_pipeline import build_analysis_graph
    from hunter.parse.run import parse_manifest
    from hunter.settings import HunterSettings

    fixture = Path(__file__).resolve().parent / "fixtures" / "wp_plugins" / "minimal_plugin"
    from hunter.ingest.walk import run_ingest
    from hunter.models.core import QuotaConfig

    settings = HunterSettings.load()
    ingest = run_ingest(fixture, QuotaConfig())
    with tempfile.TemporaryDirectory() as tmp:
        parse = parse_manifest(
            ingest.manifest,
            parse_cache_dir=Path(tmp),
            max_single_file_bytes=settings.ingest_max_single_file_bytes,
        )
    gbuild = build_graph_from_parse(ingest.manifest, parse, "3")
    g = gbuild.graph
    build_analysis_graph(
        g,
        ingest.manifest,
        parse,
        settings,
        wp_semantics_v2=False,
        resolver_enabled=False,
        cfg_ssa_enabled=False,
        taint_path_sensitive=False,
        security_popchain=False,
        structural_stats=gbuild.structural_stats,
    )
    findings = evaluators.eval_sqli_graph(g, ingest.manifest)
    assert findings, "expected SQLi finding from minimal plugin fixture"
    assert findings[0].witness.semantic_trace
    assert any(t.startswith("graph:") for t in findings[0].witness.semantic_trace)
