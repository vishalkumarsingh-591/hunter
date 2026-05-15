from __future__ import annotations

import json
from pathlib import Path

from hunter.orchestration.scan_runner import run_scan
from hunter.settings import HunterSettings

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "wp_plugins" / "minimal_plugin"


def _make_settings(tmp_path: Path) -> HunterSettings:
    return HunterSettings.load().model_copy(
        update={
            "output_root": tmp_path / "out",
            "database_url": "",
            "agents_enabled": False,
        }
    )


def test_replay_token_determinism(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    r1 = run_scan(FIXTURE, settings)
    r2 = run_scan(FIXTURE, settings)
    f1 = json.loads((r1.output_dir / "reports" / "findings.json").read_text(encoding="utf-8"))
    f2 = json.loads((r2.output_dir / "reports" / "findings.json").read_text(encoding="utf-8"))
    assert f1["replay_token"] == f2["replay_token"]
    ids1 = sorted(x["candidate"]["finding_id"] for x in f1["findings"])
    ids2 = sorted(x["candidate"]["finding_id"] for x in f2["findings"])
    assert ids1 == ids2


def test_exported_graph_nodes_include_layer_field(tmp_path: Path) -> None:
    """Layers are applied for every scan (not only when neo4j_layered_write is on)."""
    settings = _make_settings(tmp_path).model_copy(
        update={
            "neo4j_layered_write_enabled": False,
            "semantic_ir_v2_enabled": False,
            "resolver_interprocedural_enabled": False,
            "cfg_ssa_enabled": False,
            "taint_path_sensitive_enabled": False,
            "wp_semantics_v2_enabled": False,
            "security_popchain_enabled": False,
            "semantic_diff_enabled": False,
            "incremental_recompute_enabled": False,
        }
    )
    result = run_scan(FIXTURE, settings)
    nodes_path = result.output_dir / "semantic_graph" / "nodes.jsonl"
    assert nodes_path.is_file()
    first = json.loads(nodes_path.read_text(encoding="utf-8").splitlines()[0])
    assert "layer" in first


def test_phase2_flags_pipeline_smoke(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path).model_copy(
        update={
            "semantic_ir_v2_enabled": True,
            "resolver_interprocedural_enabled": True,
            "cfg_ssa_enabled": True,
            "taint_path_sensitive_enabled": True,
            "wp_semantics_v2_enabled": True,
            "security_popchain_enabled": True,
            "semantic_diff_enabled": True,
            "incremental_recompute_enabled": True,
            "neo4j_layered_write_enabled": True,
        }
    )
    result = run_scan(FIXTURE, settings)
    payload = json.loads((result.output_dir / "reports" / "findings.json").read_text(encoding="utf-8"))
    assert isinstance(payload["findings"], list)
    assert (result.output_dir / "cache" / "lineage" / "semantic_diff.json").is_file()


def test_path_sensitive_taint_still_emits_coarse_findings(tmp_path: Path) -> None:
    """Interprocedural taint must run after simple taint so Source/Sink nodes exist (regression)."""
    settings = _make_settings(tmp_path).model_copy(
        update={
            "semantic_ir_v2_enabled": True,
            "resolver_interprocedural_enabled": True,
            "cfg_ssa_enabled": True,
            "taint_path_sensitive_enabled": True,
            "wp_semantics_v2_enabled": False,
            "security_popchain_enabled": False,
            "semantic_diff_enabled": False,
            "incremental_recompute_enabled": False,
            "neo4j_layered_write_enabled": False,
        }
    )
    result = run_scan(FIXTURE, settings)
    payload = json.loads((result.output_dir / "reports" / "findings.json").read_text(encoding="utf-8"))
    rule_ids = {x["candidate"]["rule_id"] for x in payload["findings"]}
    assert "RULE-SQLI-001" in rule_ids or "RULE-XSS-001" in rule_ids
