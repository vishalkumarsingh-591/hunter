from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def write_scan_status(
    output_dir: Path,
    *,
    scan_id: str,
    status: str,
    stage: str,
    detail: str = "",
    progress_pct: float | None = None,
    error: str | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "scan_id": scan_id,
        "status": status,
        "stage": stage,
        "detail": detail,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    if progress_pct is not None:
        payload["progress_pct"] = round(progress_pct, 2)
    if error:
        payload["error"] = error
    (output_dir / "scan-status.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def read_scan_status(output_dir: Path) -> dict[str, Any] | None:
    path = output_dir / "scan-status.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
