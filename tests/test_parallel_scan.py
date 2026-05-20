from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunter.concurrency.pool import (
    resolve_max_inflight,
    resolve_max_inflight_auto,
    resolve_scan_workers,
    resolve_scan_workers_auto,
)
from hunter.concurrency.resources import SystemResources, detect_system_resources
from hunter.ingest.walk import run_ingest
from hunter.models.core import QuotaConfig
from hunter.orchestration.scan_runner import run_scan
from hunter.parse.run import parse_manifest
from hunter.settings import HunterSettings

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "wp_plugins" / "minimal_plugin"


def _make_settings(tmp_path: Path, **overrides) -> HunterSettings:
    base = HunterSettings.load().model_copy(
        update={
            "output_root": tmp_path / "out",
            "database_url": "",
            "agents_enabled": False,
        }
    )
    return base.model_copy(update=overrides)


def test_resolve_scan_workers_auto_and_serial() -> None:
    assert resolve_scan_workers(1) == 1
    assert resolve_scan_workers(4) == 4
    res = SystemResources(cpu_count=16, ram_gb=24)
    auto = resolve_scan_workers_auto(res)
    assert auto == 12
    assert resolve_scan_workers(0, resources=res) == 12


def test_resolve_max_inflight_auto() -> None:
    assert resolve_max_inflight_auto(12, 24) == 24
    assert resolve_max_inflight(0, 1) == 1
    assert resolve_max_inflight(0, 4, ram_gb=16) == 8
    assert resolve_max_inflight(16, 4) == 16


def test_detect_system_resources() -> None:
    res = detect_system_resources()
    assert res.cpu_count >= 1
    assert res.ram_gb >= 1


def test_parse_manifest_workers_equivalent(tmp_path: Path) -> None:
    from hunter.ingest.walk import run_ingest

    ingest = run_ingest(FIXTURE, QuotaConfig())
    cache = tmp_path / "cache" / "parse"
    kw = dict(
        parse_cache_dir=cache,
        max_single_file_bytes=50 * 1024 * 1024,
        structure_complete_mode=True,
        max_ir_nodes_per_file=250_000,
        lift_version="2",
    )
    r1 = parse_manifest(ingest.manifest, workers=1, **kw)
    r2 = parse_manifest(ingest.manifest, workers=2, max_inflight=4, **kw)
    d1 = {k: v.model_dump() for k, v in sorted(r1.per_file.items())}
    d2 = {k: v.model_dump() for k, v in sorted(r2.per_file.items())}
    assert d1.keys() == d2.keys()
    assert d1 == d2
    assert r1.parser_lock_hash == r2.parser_lock_hash


def test_ingest_tree_sha256_workers_equivalent() -> None:
    q = QuotaConfig()
    a = run_ingest(FIXTURE, q, workers=1)
    b = run_ingest(FIXTURE, q, workers=2)
    assert a.tree_sha256 == b.tree_sha256
    assert a.manifest.manifest_sha256 == b.manifest.manifest_sha256
    assert len(a.manifest.files) == len(b.manifest.files)


def test_replay_token_workers_equivalent(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    res = SystemResources(cpu_count=16, ram_gb=24)
    workers = resolve_scan_workers(0, resources=res)
    r1 = run_scan(FIXTURE, settings.model_copy(update={"scan_workers": 1}))
    r2 = run_scan(
        FIXTURE,
        settings.model_copy(update={"scan_workers": workers, "scan_max_inflight": 0}),
    )
    f1 = json.loads((r1.output_dir / "reports" / "findings.json").read_text(encoding="utf-8"))
    f2 = json.loads((r2.output_dir / "reports" / "findings.json").read_text(encoding="utf-8"))
    assert f1["replay_token"] == f2["replay_token"]
    ids1 = sorted(x["candidate"]["finding_id"] for x in f1["findings"])
    ids2 = sorted(x["candidate"]["finding_id"] for x in f2["findings"])
    assert ids1 == ids2


@pytest.mark.parametrize("workers", [1, 2])
def test_run_scan_completes_with_workers(tmp_path: Path, workers: int) -> None:
    settings = _make_settings(tmp_path, scan_workers=workers)
    result = run_scan(FIXTURE, settings)
    assert result.graph_integrity_ok
    assert (result.output_dir / "reports" / "findings.json").is_file()
