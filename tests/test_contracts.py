from __future__ import annotations

import json
from pathlib import Path

from hunter.contracts import (
    FINDING_ID_PATTERN,
    FINDING_REPORT_SCHEMA_VERSION,
    REPORT_TOP_LEVEL_KEYS,
    REQUIRED_FINDING_KEYS,
    has_required_keys,
)
from hunter.orchestration.scan_runner import run_scan
from hunter.settings import HunterSettings


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "wp_plugins" / "minimal_plugin"


def test_report_schema_contract_stable(tmp_path: Path) -> None:
    settings = HunterSettings.load().model_copy(
        update={
            "output_root": tmp_path / "out",
            "database_url": "",
            "agents_enabled": False,
        }
    )
    result = run_scan(FIXTURE, settings)
    payload = json.loads((result.output_dir / "reports" / "findings.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == FINDING_REPORT_SCHEMA_VERSION
    assert has_required_keys(payload, REPORT_TOP_LEVEL_KEYS)
    assert isinstance(payload["findings"], list)
    for finding in payload["findings"]:
        assert has_required_keys(finding, REQUIRED_FINDING_KEYS)
        candidate = finding["candidate"]
        assert FINDING_ID_PATTERN.match(candidate["finding_id"])
