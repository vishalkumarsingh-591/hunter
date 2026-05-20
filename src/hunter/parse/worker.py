"""Process-pool worker for per-file parse (Windows spawn-safe top-level module)."""

from __future__ import annotations

import hashlib
import json
import traceback
from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Parser

from hunter.concurrency.io import atomic_write_text
from hunter.models.ir import FileParseArtifact, ParseDiagnostic
from hunter.parse.languages import LanguageBundle, load_languages, make_parser
from hunter.parse.lift import lift_tree
from hunter.parse.lift_v2 import lift_tree_v2

_BUNDLE: LanguageBundle | None = None
_PARSERS: dict[str, Parser] = {}


@dataclass(frozen=True)
class ParseJob:
    rel_path: str
    abs_path_norm: str
    language_guess: str
    parse_cache_dir: str
    max_single_file_bytes: int
    structure_complete_mode: bool
    max_ir_nodes_per_file: int
    lift_version: str
    parser_lock_hash: str


def init_parse_worker() -> None:
    """Load grammars and parsers once per worker process."""
    global _BUNDLE, _PARSERS
    _BUNDLE = load_languages()
    _PARSERS = {}
    if _BUNDLE.php:
        _PARSERS["php"] = make_parser(_BUNDLE.php)
    if _BUNDLE.javascript:
        _PARSERS["javascript"] = make_parser(_BUNDLE.javascript)
    if _BUNDLE.html:
        _PARSERS["html"] = make_parser(_BUNDLE.html)


def _read_source(path: Path, max_bytes: int) -> tuple[bytes, str]:
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    try:
        raw.decode("utf-8")
        return raw, "utf-8"
    except UnicodeDecodeError:
        return raw, "latin-1"


def parse_one_file(job: ParseJob) -> tuple[str, FileParseArtifact]:
    """Parse a single manifest file; returns (rel_path, artifact)."""
    lock = job.parser_lock_hash
    try:
        if job.language_guess not in ("php", "javascript", "html"):
            return job.rel_path, FileParseArtifact(
                rel_path=job.rel_path,
                language=job.language_guess,  # type: ignore[arg-type]
                status="ERROR",
                diagnostics=[],
                parser_lock_hash=lock,
            )

        bundle = _BUNDLE
        if bundle is None:
            init_parse_worker()
            bundle = _BUNDLE
        assert bundle is not None

        lang = None
        if job.language_guess == "php" and bundle.php:
            lang = bundle.php
        elif job.language_guess == "javascript" and bundle.javascript:
            lang = bundle.javascript
        elif job.language_guess == "html" and bundle.html:
            lang = bundle.html

        if lang is None:
            return job.rel_path, FileParseArtifact(
                rel_path=job.rel_path,
                language=job.language_guess,  # type: ignore[arg-type]
                status="ERROR",
                diagnostics=[],
                parser_lock_hash=lock,
            )

        path = Path(job.abs_path_norm)
        cache_dir = Path(job.parse_cache_dir)
        content, _enc = _read_source(path, job.max_single_file_bytes)
        chash = hashlib.sha256(content).hexdigest()
        cache_file = cache_dir / chash[:2] / f"{chash}.json"

        if cache_file.exists():
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            return job.rel_path, FileParseArtifact.model_validate(data)

        parser = _PARSERS.get(job.language_guess)
        if parser is None:
            parser = make_parser(lang)
            _PARSERS[job.language_guess] = parser

        tree = parser.parse(content)
        if job.structure_complete_mode or job.lift_version == "2":
            nodes, edges, comments, diags, truncated = lift_tree_v2(
                tree,
                job.rel_path,
                content,
                job.language_guess,
                max_nodes=job.max_ir_nodes_per_file,
            )
            status = "PARTIAL" if truncated else "OK"
        else:
            nodes, edges, comments, diags = lift_tree(tree, job.rel_path, content, job.language_guess)
            status = "OK"
        if tree.root_node.has_error:
            status = "PARTIAL"

        art = FileParseArtifact(
            rel_path=job.rel_path,
            language=job.language_guess,  # type: ignore[arg-type]
            ir_nodes=nodes,
            ir_edges=edges,
            comments=comments,
            diagnostics=diags,
            status=status,  # type: ignore[arg-type]
            parser_lock_hash=lock,
        )
        atomic_write_text(cache_file, art.model_dump_json())
        return job.rel_path, art

    except Exception as exc:  # noqa: BLE001
        return job.rel_path, FileParseArtifact(
            rel_path=job.rel_path,
            language=job.language_guess if job.language_guess in ("php", "javascript", "html") else "php",  # type: ignore[arg-type]
            status="PARSE_CRASH",
            diagnostics=[
                ParseDiagnostic(
                    code="PARSE_CRASH",
                    message=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-500:]}",
                )
            ],
            parser_lock_hash=lock,
        )
