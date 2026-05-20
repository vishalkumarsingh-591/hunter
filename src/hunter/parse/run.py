from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path

from hunter.logging import get_logger
from hunter.models.core import RepoManifest
from hunter.models.ir import FileParseArtifact, ParseRunResult
from hunter.parse.grammar_lock import grammar_lock_hash
from hunter.parse.languages import language_for_file, load_languages
from hunter.parse.lift import lift_tree
from hunter.parse.lift_v2 import lift_tree_v2
from hunter.parse.worker import ParseJob, init_parse_worker, parse_one_file

_LOG = get_logger("hunter.parse")


def _read_source(path: Path, max_bytes: int) -> tuple[bytes, str]:
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    try:
        raw.decode("utf-8")
        return raw, "utf-8"
    except UnicodeDecodeError:
        return raw, "latin-1"


def _parse_one_serial(
    mf,
    *,
    bundle,
    lock: str,
    parse_cache_dir: Path,
    max_single_file_bytes: int,
    structure_complete_mode: bool,
    max_ir_nodes_per_file: int,
    lift_version: str,
) -> FileParseArtifact:
    path = Path(mf.abs_path_norm)
    lang, _mk = language_for_file(bundle, mf.language_guess)
    if lang is None:
        return FileParseArtifact(
            rel_path=mf.rel_path,
            language=mf.language_guess,  # type: ignore[arg-type]
            status="ERROR",
            diagnostics=[],
            parser_lock_hash=lock,
        )
    content, _enc = _read_source(path, max_single_file_bytes)
    chash = hashlib.sha256(content).hexdigest()
    cache_file = parse_cache_dir / chash[:2] / f"{chash}.json"
    if cache_file.exists():
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        return FileParseArtifact.model_validate(data)
    from tree_sitter import Parser

    parser = Parser()
    parser.language = lang
    tree = parser.parse(content)
    if structure_complete_mode or lift_version == "2":
        nodes, edges, comments, diags, truncated = lift_tree_v2(
            tree, mf.rel_path, content, mf.language_guess, max_nodes=max_ir_nodes_per_file
        )
        status = "PARTIAL" if truncated else "OK"
    else:
        nodes, edges, comments, diags = lift_tree(tree, mf.rel_path, content, mf.language_guess)
        status = "OK"
    if tree.root_node.has_error:
        status = "PARTIAL"
    art = FileParseArtifact(
        rel_path=mf.rel_path,
        language=mf.language_guess,  # type: ignore[arg-type]
        ir_nodes=nodes,
        ir_edges=edges,
        comments=comments,
        diagnostics=diags,
        status=status,  # type: ignore[arg-type]
        parser_lock_hash=lock,
    )
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(art.model_dump_json(), encoding="utf-8")
    return art


def _build_parse_jobs(
    manifest: RepoManifest,
    *,
    parse_cache_dir: Path,
    max_single_file_bytes: int,
    structure_complete_mode: bool,
    max_ir_nodes_per_file: int,
    lift_version: str,
    parser_lock_hash: str,
) -> list[ParseJob]:
    jobs: list[ParseJob] = []
    for mf in manifest.files:
        if mf.parse_policy != "parse":
            continue
        if mf.language_guess not in ("php", "javascript", "html"):
            continue
        jobs.append(
            ParseJob(
                rel_path=mf.rel_path,
                abs_path_norm=mf.abs_path_norm,
                language_guess=mf.language_guess,
                parse_cache_dir=str(parse_cache_dir.resolve()),
                max_single_file_bytes=max_single_file_bytes,
                structure_complete_mode=structure_complete_mode,
                max_ir_nodes_per_file=max_ir_nodes_per_file,
                lift_version=lift_version,
                parser_lock_hash=parser_lock_hash,
            )
        )
    return jobs


def _parse_manifest_parallel(
    jobs: list[ParseJob],
    *,
    workers: int,
    max_inflight: int,
    progress: Callable[[int, str | None], None] | None,
) -> dict[str, FileParseArtifact]:
    per_file: dict[str, FileParseArtifact] = {}

    with ProcessPoolExecutor(max_workers=workers, initializer=init_parse_worker) as pool:
        pending: dict = {}
        job_iter = iter(jobs)
        jobs_exhausted = False

        def submit_next() -> None:
            nonlocal jobs_exhausted
            if jobs_exhausted:
                return
            try:
                job = next(job_iter)
            except StopIteration:
                jobs_exhausted = True
                return
            pending[pool.submit(parse_one_file, job)] = job

        for _ in range(min(max_inflight, len(jobs))):
            submit_next()

        while pending:
            done, _ = wait(pending.keys(), return_when=FIRST_COMPLETED)
            for future in done:
                job = pending.pop(future)
                rel_path, art = future.result()
                per_file[rel_path] = art
                desc = f"parsed {rel_path}"
                if progress:
                    progress(1, desc)
                submit_next()

    _LOG.info(
        "parse_parallel_complete",
        workers=workers,
        max_inflight=max_inflight,
        files=len(per_file),
    )
    return per_file


def parse_manifest(
    manifest: RepoManifest,
    *,
    parse_cache_dir: Path,
    max_single_file_bytes: int,
    progress: Callable[[int, str | None], None] | None = None,
    structure_complete_mode: bool = True,
    max_ir_nodes_per_file: int = 250_000,
    lift_version: str = "2",
    workers: int = 1,
    max_inflight: int = 0,
) -> ParseRunResult:
    bundle = load_languages()
    lock = grammar_lock_hash()
    per_file: dict[str, FileParseArtifact] = {}
    if bundle.load_errors:
        _LOG.warning("grammar_load_partial", errors=bundle.load_errors)

    if workers > 1:
        from hunter.concurrency.pool import resolve_max_inflight

        inflight = resolve_max_inflight(max_inflight, workers)
        jobs = _build_parse_jobs(
            manifest,
            parse_cache_dir=parse_cache_dir,
            max_single_file_bytes=max_single_file_bytes,
            structure_complete_mode=structure_complete_mode,
            max_ir_nodes_per_file=max_ir_nodes_per_file,
            lift_version=lift_version,
            parser_lock_hash=lock,
        )
        per_file = _parse_manifest_parallel(
            jobs,
            workers=workers,
            max_inflight=inflight,
            progress=progress,
        )
        _LOG.info("parse_parallel_workers", workers=workers, max_inflight=inflight, file_count=len(per_file))
        return ParseRunResult(per_file=per_file, parser_lock_hash=lock)

    for mf in manifest.files:
        if mf.parse_policy != "parse":
            continue
        if mf.language_guess not in ("php", "javascript", "html"):
            continue
        art = _parse_one_serial(
            mf,
            bundle=bundle,
            lock=lock,
            parse_cache_dir=parse_cache_dir,
            max_single_file_bytes=max_single_file_bytes,
            structure_complete_mode=structure_complete_mode,
            max_ir_nodes_per_file=max_ir_nodes_per_file,
            lift_version=lift_version,
        )
        per_file[mf.rel_path] = art
        if progress:
            progress(1, f"parsed {mf.rel_path}")
    return ParseRunResult(per_file=per_file, parser_lock_hash=lock)
