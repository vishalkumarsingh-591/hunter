from __future__ import annotations

from dataclasses import dataclass, field

from hunter.models.core import RepoManifest


@dataclass
class SemanticDiffResult:
    added_files: list[str] = field(default_factory=list)
    removed_files: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    unchanged_files: list[str] = field(default_factory=list)


def compute_semantic_diff(base: RepoManifest | None, target: RepoManifest) -> SemanticDiffResult:
    """Deterministic file-hash diff baseline for semantic lineage."""
    out = SemanticDiffResult()
    if base is None:
        out.added_files = sorted(f.rel_path for f in target.files)
        return out
    base_map = {f.rel_path: f.sha256 for f in base.files}
    target_map = {f.rel_path: f.sha256 for f in target.files}
    base_paths = set(base_map)
    target_paths = set(target_map)
    out.added_files = sorted(target_paths - base_paths)
    out.removed_files = sorted(base_paths - target_paths)
    shared = sorted(base_paths & target_paths)
    for rel in shared:
        if base_map[rel] == target_map[rel]:
            out.unchanged_files.append(rel)
        else:
            out.changed_files.append(rel)
    return out
