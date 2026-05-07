from __future__ import annotations

import hashlib
from pathlib import Path

from hunter.ingest.errors import QuotaExceeded
from hunter.ingest.manifest import finalize_manifest
from hunter.logging import get_logger
from hunter.models.core import (
    IngestDiagnostic,
    IngestResult,
    IngestStatus,
    QuotaConfig,
    RepoManifestFile,
)

_LOG = get_logger("hunter.ingest")

_TEXT_EXT = {".php", ".phtml", ".inc"}
_JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
_HTML_EXT = {".html", ".htm"}


def _language_guess(path: Path) -> str:
    suf = path.suffix.lower()
    if suf in _TEXT_EXT:
        return "php"
    if suf in _JS_EXT:
        return "javascript"
    if suf in _HTML_EXT:
        return "html"
    return "other"


def _is_probably_binary(sample: bytes) -> bool:
    if b"\x00" in sample[:8192]:
        return True
    return False


def _hash_file(path: Path, max_read: int) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_read:
                raise QuotaExceeded(f"file exceeds max_single_file_bytes: {path}")
            h.update(chunk)
    return h.hexdigest(), total


def run_ingest(root: Path, quotas: QuotaConfig) -> IngestResult:
    root = root.resolve()
    if not root.is_dir():
        return IngestResult(
            status=IngestStatus.FAILED,
            manifest=finalize_manifest(str(root), []),
            diagnostics=[
                IngestDiagnostic(path=str(root), code="NOT_A_DIRECTORY", message="plugin root must be a directory")
            ],
        )
    diagnostics: list[IngestDiagnostic] = []
    files: list[RepoManifestFile] = []
    total_bytes = 0
    stopped_at: str | None = None
    status = IngestStatus.SUCCESS

    def walk_fixed(cur: Path, rel: str, depth: int) -> None:
        nonlocal total_bytes, status, stopped_at
        if depth > quotas.max_depth:
            diagnostics.append(
                IngestDiagnostic(
                    path=rel or ".",
                    code="MAX_DEPTH",
                    message=f"max_depth {quotas.max_depth} exceeded",
                )
            )
            return
        try:
            entries = sorted(cur.iterdir(), key=lambda p: p.name.lower())
        except OSError as e:
            diagnostics.append(
                IngestDiagnostic(path=rel or ".", code="LISTDIR_ERROR", message=str(e))
            )
            return
        for entry in entries:
            name = entry.name
            child_rel = f"{rel}/{name}" if rel else name
            if entry.is_symlink() and not quotas.follow_symlinks:
                try:
                    target = entry.resolve()
                    if root not in target.parents and target != root:
                        diagnostics.append(
                            IngestDiagnostic(
                                path=child_rel,
                                code="SYMLINK_SKIPPED",
                                message="external symlink skipped",
                            )
                        )
                        continue
                except OSError:
                    diagnostics.append(
                        IngestDiagnostic(path=child_rel, code="SYMLINK_ERROR", message="could not resolve symlink")
                    )
                    continue
            if entry.is_dir():
                walk_fixed(entry.resolve(), child_rel, depth + 1)
                continue
            if not entry.is_file():
                continue
            if len(files) >= quotas.max_files:
                status = IngestStatus.PARTIAL
                stopped_at = child_rel
                diagnostics.append(
                    IngestDiagnostic(
                        path=child_rel,
                        code="MAX_FILES",
                        message=f"max_files {quotas.max_files}",
                    )
                )
                raise QuotaExceeded("max_files")
            try:
                st = entry.stat()
            except OSError as e:
                diagnostics.append(IngestDiagnostic(path=child_rel, code="STAT_ERROR", message=str(e)))
                continue
            if st.st_size > quotas.max_single_file_bytes:
                diagnostics.append(
                    IngestDiagnostic(
                        path=child_rel,
                        code="FILE_TOO_LARGE",
                        message="skipped: exceeds max_single_file_bytes",
                    )
                )
                files.append(
                    RepoManifestFile(
                        rel_path=child_rel,
                        abs_path_norm=str(entry.resolve()),
                        sha256="",
                        size=st.st_size,
                        mtime_ns=getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)),
                        language_guess="other",
                        parse_policy="skip_size",
                    )
                )
                continue
            if total_bytes + st.st_size > quotas.max_total_bytes:
                status = IngestStatus.PARTIAL
                stopped_at = child_rel
                diagnostics.append(
                    IngestDiagnostic(
                        path=child_rel,
                        code="MAX_TOTAL_BYTES",
                        message="quota exceeded",
                    )
                )
                raise QuotaExceeded("max_total_bytes")
            lang = _language_guess(entry)
            policy: str = "parse"
            enc = "utf-8"
            if lang == "other":
                try:
                    sample = entry.open("rb").read(4096)
                except OSError as e:
                    diagnostics.append(IngestDiagnostic(path=child_rel, code="READ_ERROR", message=str(e)))
                    continue
                if _is_probably_binary(sample):
                    files.append(
                        RepoManifestFile(
                            rel_path=child_rel,
                            abs_path_norm=str(entry.resolve()),
                            sha256=hashlib.sha256(sample).hexdigest(),
                            size=st.st_size,
                            mtime_ns=getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)),
                            language_guess="binary",
                            parse_policy="skip_binary",
                        )
                    )
                    continue
            try:
                digest, nbytes = _hash_file(entry, quotas.max_single_file_bytes)
            except QuotaExceeded:
                status = IngestStatus.PARTIAL
                stopped_at = child_rel
                diagnostics.append(
                    IngestDiagnostic(path=child_rel, code="HASH_ABORT", message="file grew beyond quota during hash")
                )
                raise
            total_bytes += nbytes
            if lang == "other":
                try:
                    entry.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    enc = "binary-ambiguous"
                    policy = "skip_encoding"
                    lang = "other"
            files.append(
                RepoManifestFile(
                    rel_path=child_rel,
                    abs_path_norm=str(entry.resolve()),
                    sha256=digest,
                    size=st.st_size,
                    mtime_ns=getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)),
                    language_guess=lang if lang != "binary" else "binary",
                    encoding=enc,
                    parse_policy=policy if lang in ("php", "javascript", "html") else policy,
                )
            )

    try:
        walk_fixed(root, "", 0)
    except QuotaExceeded:
        pass

    manifest = finalize_manifest(str(root), files)
    tree_hash = hashlib.sha256()
    for f in manifest.files:
        tree_hash.update(f.rel_path.encode("utf-8"))
        tree_hash.update(b"\0")
        tree_hash.update(f.sha256.encode("ascii"))
        tree_hash.update(b"\n")
    _LOG.info("ingest_completed", file_count=len(files), status=status.value)
    return IngestResult(
        status=status,
        manifest=manifest,
        diagnostics=diagnostics,
        stopped_at_path=stopped_at,
        tree_sha256=tree_hash.hexdigest(),
    )
