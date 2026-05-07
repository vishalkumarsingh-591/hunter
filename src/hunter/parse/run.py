from __future__ import annotations

import hashlib
import json
from pathlib import Path

from hunter.logging import get_logger
from hunter.models.core import RepoManifest
from hunter.models.ir import FileParseArtifact, ParseRunResult
from hunter.parse.grammar_lock import grammar_lock_hash
from hunter.parse.languages import language_for_file, load_languages
from hunter.parse.lift import lift_tree

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


def parse_manifest(
    manifest: RepoManifest,
    *,
    parse_cache_dir: Path,
    max_single_file_bytes: int,
) -> ParseRunResult:
    bundle = load_languages()
    lock = grammar_lock_hash()
    per_file: dict[str, FileParseArtifact] = {}
    if bundle.load_errors:
        _LOG.warning("grammar_load_partial", errors=bundle.load_errors)
    for mf in manifest.files:
        if mf.parse_policy != "parse":
            continue
        if mf.language_guess not in ("php", "javascript", "html"):
            continue
        path = Path(mf.abs_path_norm)
        lang, _mk = language_for_file(bundle, mf.language_guess)
        if lang is None:
            per_file[mf.rel_path] = FileParseArtifact(
                rel_path=mf.rel_path,
                language=mf.language_guess,  # type: ignore[arg-type]
                status="ERROR",
                diagnostics=[],
                parser_lock_hash=lock,
            )
            continue
        content, _enc = _read_source(path, max_single_file_bytes)
        chash = hashlib.sha256(content).hexdigest()
        cache_file = parse_cache_dir / chash[:2] / f"{chash}.json"
        if cache_file.exists():
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            per_file[mf.rel_path] = FileParseArtifact.model_validate(data)
            continue
        from tree_sitter import Parser

        parser = Parser()
        parser.language = lang
        tree = parser.parse(content)
        nodes, edges, comments, diags = lift_tree(tree, mf.rel_path, content, mf.language_guess)
        status: str = "OK"
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
        per_file[mf.rel_path] = art
    return ParseRunResult(per_file=per_file, parser_lock_hash=lock)
