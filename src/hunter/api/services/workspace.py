from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from hunter.api.services.github_client import resolve_plugin_root


def extract_upload(archive_path: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    if archive_path.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest)
    else:
        shutil.copy2(archive_path, dest / archive_path.name)
    return resolve_plugin_root(dest)


def save_upload_stream(dest_file: Path, chunks) -> None:
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    with open(dest_file, "wb") as f:
        for chunk in chunks:
            f.write(chunk)


def save_folder_files(dest_root: Path, files: list[tuple[str, bytes]]) -> Path:
    """Write relative paths from a browser folder upload into dest_root."""
    dest_root.mkdir(parents=True, exist_ok=True)
    for rel_path, data in files:
        safe = rel_path.replace("\\", "/").lstrip("/")
        if ".." in safe.split("/"):
            continue
        target = dest_root / safe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return resolve_plugin_root(dest_root)
