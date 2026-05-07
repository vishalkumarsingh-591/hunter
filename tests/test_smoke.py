from __future__ import annotations

from pathlib import Path

from hunter.orchestration.scan_runner import run_scan
from hunter.settings import HunterSettings


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "wp_plugins" / "minimal_plugin"


def test_scan_smoke(tmp_path: Path) -> None:
    settings = HunterSettings.load()
    settings = settings.model_copy(
        update={
            "output_root": tmp_path / "out",
            "database_url": "",
            "agents_enabled": False,
        }
    )
    result = run_scan(FIXTURE, settings)
    assert result.scan_id
    assert (result.output_dir / "reports" / "findings.json").is_file()
    assert (result.output_dir / "repository_snapshot" / "files.jsonl").is_file()
