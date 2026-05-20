from __future__ import annotations

import json
import shutil
from pathlib import Path

from hunter.concurrency.pool import run_threaded_map
from hunter.models.core import IngestResult, RepoManifest, SnapshotMode


def _copy_one_file(args: tuple[Path, Path]) -> None:
    src, dst = args
    if not src.is_file():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(src, dst)
    except OSError:
        pass


def write_repository_snapshot(
    output_dir: Path,
    manifest: RepoManifest,
    ingest_result: IngestResult,
    snapshot_mode: SnapshotMode,
    *,
    workers: int = 1,
) -> None:
    snap_dir = output_dir / "repository_snapshot"
    snap_dir.mkdir(parents=True, exist_ok=True)
    files_jsonl = snap_dir / "files.jsonl"
    with open(files_jsonl, "w", encoding="utf-8") as out:
        for f in manifest.files:
            out.write(json.dumps(f.model_dump(), sort_keys=True) + "\n")
    with open(snap_dir / "tree.sha256", "w", encoding="utf-8") as out:
        out.write(ingest_result.tree_sha256 + "\n")
    meta = {
        "status": ingest_result.status.value,
        "root_path_norm": manifest.root_path_norm,
        "manifest_sha256": manifest.manifest_sha256,
        "diagnostics": [d.model_dump() for d in ingest_result.diagnostics],
        "stopped_at_path": ingest_result.stopped_at_path,
    }
    with open(snap_dir / "INGEST_META.json", "w", encoding="utf-8") as out:
        json.dump(meta, out, indent=2, sort_keys=True)
    if snapshot_mode == SnapshotMode.copy:
        dest_root = snap_dir / "files_copy"
        dest_root.mkdir(exist_ok=True)
        root = Path(manifest.root_path_norm)
        copy_jobs: list[tuple[Path, Path]] = []
        for f in manifest.files:
            if f.language_guess == "binary":
                continue
            src = root / f.rel_path
            dst = dest_root / f.rel_path
            copy_jobs.append((src, dst))
        if workers <= 1:
            for job in copy_jobs:
                _copy_one_file(job)
        else:
            run_threaded_map(copy_jobs, _copy_one_file, workers=workers)
