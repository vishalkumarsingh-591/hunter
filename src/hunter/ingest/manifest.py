from __future__ import annotations

import hashlib
import json

from hunter.models.core import RepoManifest, RepoManifestFile


def build_manifest_sha256(files: tuple[RepoManifestFile, ...]) -> str:
    payload = [
        {
            "rel_path": f.rel_path,
            "sha256": f.sha256,
            "size": f.size,
            "language_guess": f.language_guess,
        }
        for f in files
    ]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def finalize_manifest(root_path_norm: str, files: list[RepoManifestFile]) -> RepoManifest:
    sorted_files = tuple(sorted(files, key=lambda f: f.rel_path))
    mh = build_manifest_sha256(sorted_files)
    return RepoManifest(root_path_norm=root_path_norm, files=sorted_files, manifest_sha256=mh)
