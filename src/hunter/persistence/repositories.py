from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from hunter.persistence.database import AuditEventRow, FindingRow, ScanRow


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def upsert_scan_start(self, row: ScanRow) -> None:
        self.s.merge(row)

    def finish_scan(self, scan_id: str, status: str, snapshot_id: str | None, replay_token: str | None) -> None:
        r = self.s.get(ScanRow, scan_id)
        if r:
            r.status = status
            r.snapshot_id = snapshot_id
            r.replay_token = replay_token

    def insert_findings(self, scan_id: str, findings: list[dict[str, Any]]) -> None:
        for f in findings:
            self.s.merge(
                FindingRow(
                    id=f["finding_id"],
                    scan_id=scan_id,
                    rule_id=f["rule_id"],
                    severity=f.get("severity_band_static", "INFO"),
                    payload=f,
                )
            )


class AuditRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def append(self, event_type: str, scan_id: str | None, payload: dict) -> None:
        self.s.add(
            AuditEventRow(
                event_type=event_type,
                scan_id=scan_id,
                payload_json=payload,
            )
        )
