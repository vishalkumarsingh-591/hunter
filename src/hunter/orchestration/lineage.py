from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from hunter.analysis.semantic.diff import SemanticDiffResult, compute_semantic_diff
from hunter.models.core import RepoManifest


@dataclass
class LineageResult:
    base_snapshot_id: str | None
    semantic_diff: SemanticDiffResult


def _read_previous_manifest(out_dir: Path) -> RepoManifest | None:
    f = out_dir / "cache" / "lineage" / "previous_manifest.json"
    if not f.exists():
        return None
    return RepoManifest.model_validate_json(f.read_text(encoding="utf-8"))


def compute_lineage(out_dir: Path, manifest: RepoManifest) -> LineageResult:
    base_manifest = _read_previous_manifest(out_dir)
    diff = compute_semantic_diff(base_manifest, manifest)
    lineage_dir = out_dir / "cache" / "lineage"
    lineage_dir.mkdir(parents=True, exist_ok=True)
    (lineage_dir / "semantic_diff.json").write_text(json.dumps(diff.__dict__, indent=2, sort_keys=True), encoding="utf-8")
    (lineage_dir / "previous_manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")
    base_snapshot_id = None
    sid = out_dir / "semantic_graph" / "snapshot_id.txt"
    if sid.exists():
        base_snapshot_id = sid.read_text(encoding="utf-8").strip() or None
    return LineageResult(base_snapshot_id=base_snapshot_id, semantic_diff=diff)
