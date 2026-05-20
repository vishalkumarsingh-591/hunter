from __future__ import annotations

from pathlib import Path

import pytest

from hunter.analysis.rules.loader import load_rule_pack
from hunter.graph.security_facts_catalog import catalog_hash, load_catalog, merge_catalogs
from hunter.orchestration.scan_runner import resolve_scan_profile
from hunter.settings import HunterSettings


def test_catalog_merge_stable_hash() -> None:
    h1 = catalog_hash(["generic-php-v1", "wordpress-v1"])
    h2 = catalog_hash(["generic-php-v1", "wordpress-v1"])
    assert h1 == h2
    _merged, compiled = merge_catalogs(["generic-php-v1", "wordpress-v1"])
    assert any(p[0] == "Sink" and p[2].get("api") == "wpdb_query" for p in compiled)


def test_load_generic_catalog() -> None:
    cat = load_catalog("generic-php-v1")
    assert "php" in cat.languages
    assert len(cat.patterns) > 5


def test_profile_detect_wordpress() -> None:
    root = Path(__file__).resolve().parent / "fixtures" / "wp_plugins" / "minimal_plugin"
    from hunter.ingest.walk import run_ingest
    from hunter.models.core import QuotaConfig

    ingest = run_ingest(
        root, QuotaConfig(max_files=100, max_total_bytes=10_000_000, max_single_file_bytes=1_000_000, max_depth=8)
    )
    profile = resolve_scan_profile(root, "auto", ingest.manifest.files)
    assert profile.profile_id == "full"
    assert "wordpress" in profile.adapter_ids


def test_profile_detect_generic() -> None:
    root = Path(__file__).resolve().parent / "fixtures" / "php_generic"
    from hunter.ingest.walk import run_ingest
    from hunter.models.core import QuotaConfig

    ingest = run_ingest(
        root, QuotaConfig(max_files=100, max_total_bytes=10_000_000, max_single_file_bytes=1_000_000, max_depth=8)
    )
    profile = resolve_scan_profile(root, "auto", ingest.manifest.files)
    assert profile.profile_id == "generic-php"
    assert profile.adapter_ids == []


def test_rule_pack_includes() -> None:
    packs_dir = Path(__file__).resolve().parents[1] / "src" / "hunter" / "analysis" / "rules" / "packs"
    full = load_rule_pack(packs_dir / "full.yaml")
    ids = {r.id for r in full.rules}
    assert "RULE-SQLI-001" in ids
    assert "RULE-WP-AJAX-001" in ids
    generic = load_rule_pack(packs_dir / "generic-php.yaml")
    gids = {r.id for r in generic.rules}
    assert "RULE-SQLI-001" in gids
    assert "RULE-WP-AJAX-001" not in gids


@pytest.mark.slow
def test_scan_generic_pdo_sqli() -> None:
    root = Path(__file__).resolve().parent / "fixtures" / "php_generic"
    settings = HunterSettings.load()
    settings = settings.model_copy(
        update={
            "scan_profile": "generic-php",
            "output_root": Path("output"),
            "graph_schema_version": "3.1",
            "semantic_ir_v2_enabled": True,
            "resolver_interprocedural_enabled": True,
            "cfg_ssa_enabled": True,
            "taint_path_sensitive_enabled": True,
            "security_popchain_enabled": True,
        }
    )
    from hunter.orchestration.scan_runner import run_scan

    result = run_scan(root, settings)
    candidates = (result.output_dir / "findings" / "candidates.jsonl").read_text(encoding="utf-8")
    assert "RULE-SQLI-001" in candidates
