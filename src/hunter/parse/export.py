from __future__ import annotations

from pathlib import Path

from hunter.concurrency.pool import run_threaded_map
from hunter.models.ir import ParseRunResult


def _write_ir_file(item: tuple[str, str, Path]) -> None:
    _rel, json_text, out_path = item
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json_text, encoding="utf-8")


def export_ir_artifacts(parse: ParseRunResult, ir_dir: Path, *, workers: int = 1) -> None:
    """Write per-file IR JSON under ir_dir (parallel when workers > 1)."""
    ir_dir.mkdir(parents=True, exist_ok=True)
    items: list[tuple[str, str, Path]] = []
    for rel, art in parse.per_file.items():
        safe = rel.replace("\\", "_").replace("/", "__")
        items.append((rel, art.model_dump_json(), ir_dir / f"{safe}.json"))

    if workers <= 1:
        for _rel, json_text, out_path in items:
            _write_ir_file((_rel, json_text, out_path))
        return

    run_threaded_map(items, _write_ir_file, workers=workers)
