from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from hunter.persistence.database import AuditEventRow, FindingRow, ScanRow


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def upsert_scan_start(self, row: ScanRow) -> None:
        self.s.merge(row)

    def finish_scan(
        self,
        scan_id: str,
        status: str,
        snapshot_id: str | None,
        replay_token: str | None,
        *,
        output_dir: str | None = None,
        findings_count: int = 0,
        error_message: str | None = None,
    ) -> None:
        r = self.s.get(ScanRow, scan_id)
        if r:
            r.status = status
            r.snapshot_id = snapshot_id
            r.replay_token = replay_token
            r.finished_at = datetime.now(UTC)
            if output_dir is not None:
                r.output_dir = output_dir
            r.findings_count = findings_count
            if error_message is not None:
                r.error_message = error_message

    def mark_failed(self, scan_id: str, error_message: str) -> None:
        r = self.s.get(ScanRow, scan_id)
        if r:
            r.status = "FAILED"
            r.error_message = error_message
            r.finished_at = datetime.now(UTC)

    def get(self, scan_id: str) -> ScanRow | None:
        return self.s.get(ScanRow, scan_id)

    def list_scans(self, *, limit: int = 50, offset: int = 0) -> list[ScanRow]:
        stmt = select(ScanRow).order_by(ScanRow.started_at.desc()).limit(limit).offset(offset)
        return list(self.s.scalars(stmt).all())

    def count_scans(self) -> int:
        return int(self.s.scalar(select(func.count()).select_from(ScanRow)) or 0)

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

    def delete_scan(self, scan_id: str) -> bool:
        self.s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
        self.s.execute(delete(AuditEventRow).where(AuditEventRow.scan_id == scan_id))
        row = self.s.get(ScanRow, scan_id)
        if row is None:
            return False
        self.s.delete(row)
        return True


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def list_for_scan(
        self,
        scan_id: str,
        *,
        severity: str | None = None,
        rule_id: str | None = None,
        vuln_type: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[FindingRow]:
        stmt = select(FindingRow).where(FindingRow.scan_id == scan_id)
        if severity:
            stmt = stmt.where(FindingRow.severity == severity.upper())
        if rule_id:
            stmt = stmt.where(FindingRow.rule_id == rule_id)
        if vuln_type:
            stmt = stmt.where(FindingRow.rule_id.like(f"RULE-{vuln_type.upper()}-%"))
        stmt = stmt.order_by(FindingRow.severity, FindingRow.rule_id).limit(limit).offset(offset)
        return list(self.s.scalars(stmt).all())

    def count_for_scan(
        self,
        scan_id: str,
        *,
        severity: str | None = None,
        rule_id: str | None = None,
        vuln_type: str | None = None,
    ) -> int:
        stmt = select(func.count()).select_from(FindingRow).where(FindingRow.scan_id == scan_id)
        if severity:
            stmt = stmt.where(FindingRow.severity == severity.upper())
        if rule_id:
            stmt = stmt.where(FindingRow.rule_id == rule_id)
        if vuln_type:
            stmt = stmt.where(FindingRow.rule_id.like(f"RULE-{vuln_type.upper()}-%"))
        return int(self.s.scalar(stmt) or 0)

    def severity_counts(self, scan_id: str) -> dict[str, int]:
        rows = self.s.execute(
            select(FindingRow.severity, func.count())
            .where(FindingRow.scan_id == scan_id)
            .group_by(FindingRow.severity)
        ).all()
        return {str(sev): int(cnt) for sev, cnt in rows}

    def rule_counts(self, scan_id: str) -> dict[str, int]:
        rows = self.s.execute(
            select(FindingRow.rule_id, func.count())
            .where(FindingRow.scan_id == scan_id)
            .group_by(FindingRow.rule_id)
        ).all()
        return {str(rid): int(cnt) for rid, cnt in rows}

    def delete_for_scan(self, scan_id: str) -> None:
        self.s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))


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
