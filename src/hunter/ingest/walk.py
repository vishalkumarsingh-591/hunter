from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from hunter.concurrency.pool import run_threaded_map
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


@dataclass
class _PendingHash:
    rel_path: str
    abs_path: Path
    size: int
    mtime_ns: int
    language_guess: str
    encoding: str
    parse_policy: str


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


def _hash_pending(entry: _PendingHash, max_read: int) -> tuple[str, tuple[str, int] | BaseException]:
    try:
        digest, nbytes = _hash_file(entry.abs_path, max_read)
        return entry.rel_path, (digest, nbytes)
    except QuotaExceeded as exc:
        return entry.rel_path, exc


def _finalize_pending_serial(
    pending: list[_PendingHash],
    *,
    files: list[RepoManifestFile],
    quotas: QuotaConfig,
    total_bytes: int,
    diagnostics: list[IngestDiagnostic],
    status: IngestStatus,
    stopped_at: str | None,
) -> tuple[int, IngestStatus, str | None]:
    for entry in pending:
        try:
            digest, nbytes = _hash_file(entry.abs_path, quotas.max_single_file_bytes)
        except QuotaExceeded:
            status = IngestStatus.PARTIAL
            stopped_at = entry.rel_path
            diagnostics.append(
                IngestDiagnostic(
                    path=entry.rel_path,
                    code="HASH_ABORT",
                    message="file grew beyond quota during hash",
                )
            )
            raise QuotaExceeded("hash_abort") from None
        total_bytes += nbytes
        files.append(
            RepoManifestFile(
                rel_path=entry.rel_path,
                abs_path_norm=str(entry.abs_path.resolve()),
                sha256=digest,
                size=entry.size,
                mtime_ns=entry.mtime_ns,
                language_guess=entry.language_guess,  # type: ignore[arg-type]
                encoding=entry.encoding,
                parse_policy=entry.parse_policy,  # type: ignore[arg-type]
            )
        )
    return total_bytes, status, stopped_at


def _finalize_pending_parallel(
    pending: list[_PendingHash],
    *,
    files: list[RepoManifestFile],
    quotas: QuotaConfig,
    total_bytes: int,
    diagnostics: list[IngestDiagnostic],
    status: IngestStatus,
    stopped_at: str | None,
    workers: int,
) -> tuple[int, IngestStatus, str | None]:
    if not pending:
        return total_bytes, status, stopped_at

    hashed: dict[str, tuple[str, int] | BaseException] = {}
    results = run_threaded_map(
        pending,
        lambda e: _hash_pending(e, quotas.max_single_file_bytes),
        workers=workers,
    )
    for rel_path, outcome in results:
        hashed[rel_path] = outcome

    for entry in pending:
        outcome = hashed[entry.rel_path]
        if isinstance(outcome, QuotaExceeded):
            status = IngestStatus.PARTIAL
            stopped_at = entry.rel_path
            diagnostics.append(
                IngestDiagnostic(
                    path=entry.rel_path,
                    code="HASH_ABORT",
                    message="file grew beyond quota during hash",
                )
            )
            raise QuotaExceeded("hash_abort") from None
        digest, nbytes = outcome
        total_bytes += nbytes
        files.append(
            RepoManifestFile(
                rel_path=entry.rel_path,
                abs_path_norm=str(entry.abs_path.resolve()),
                sha256=digest,
                size=entry.size,
                mtime_ns=entry.mtime_ns,
                language_guess=entry.language_guess,  # type: ignore[arg-type]
                encoding=entry.encoding,
                parse_policy=entry.parse_policy,  # type: ignore[arg-type]
            )
        )
    return total_bytes, status, stopped_at


def run_ingest(root: Path, quotas: QuotaConfig, *, workers: int = 1) -> IngestResult:
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
    pending_hash: list[_PendingHash] = []
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
            diagnostics.append(IngestDiagnostic(path=rel or ".", code="LISTDIR_ERROR", message=str(e)))
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
            if len(files) + len(pending_hash) >= quotas.max_files:
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
            pending_hash.append(
                _PendingHash(
                    rel_path=child_rel,
                    abs_path=entry.resolve(),
                    size=st.st_size,
                    mtime_ns=getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)),
                    language_guess=lang if lang != "binary" else "other",
                    encoding=enc,
                    parse_policy=policy,
                )
            )

    try:
        walk_fixed(root, "", 0)
    except QuotaExceeded:
        pass

    # encoding / skip_encoding probe for "other" text files (walk order)
    finalized_pending: list[_PendingHash] = []
    for entry in pending_hash:
        if entry.language_guess == "other":
            try:
                entry.abs_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                files.append(
                    RepoManifestFile(
                        rel_path=entry.rel_path,
                        abs_path_norm=str(entry.abs_path.resolve()),
                        sha256="",
                        size=entry.size,
                        mtime_ns=entry.mtime_ns,
                        language_guess="other",
                        encoding="binary-ambiguous",
                        parse_policy="skip_encoding",
                    )
                )
                continue
        finalized_pending.append(entry)

    try:
        if workers > 1:
            total_bytes, status, stopped_at = _finalize_pending_parallel(
                finalized_pending,
                files=files,
                quotas=quotas,
                total_bytes=total_bytes,
                diagnostics=diagnostics,
                status=status,
                stopped_at=stopped_at,
                workers=workers,
            )
            _LOG.info("ingest_hash_parallel", workers=workers, pending=len(finalized_pending))
        else:
            total_bytes, status, stopped_at = _finalize_pending_serial(
                finalized_pending,
                files=files,
                quotas=quotas,
                total_bytes=total_bytes,
                diagnostics=diagnostics,
                status=status,
                stopped_at=stopped_at,
            )
    except QuotaExceeded:
        pass

    manifest = finalize_manifest(str(root), files)
    tree_hash = hashlib.sha256()
    for f in manifest.files:
        tree_hash.update(f.rel_path.encode("utf-8"))
        tree_hash.update(b"\0")
        tree_hash.update(f.sha256.encode("ascii"))
        tree_hash.update(b"\n")
    _LOG.info("ingest_completed", file_count=len(files), status=status.value, ingest_hash_workers=workers)
    return IngestResult(
        status=status,
        manifest=manifest,
        diagnostics=diagnostics,
        stopped_at_path=stopped_at,
        tree_sha256=tree_hash.hexdigest(),
    )
