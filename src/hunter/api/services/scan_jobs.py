from __future__ import annotations

import json
import shutil
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from hunter.api.schemas import FindingSummary, FindingsPage, ScanDetail, ScanSummary
from hunter.api.services.vuln_types import title_from_rule, vuln_type_from_rule
from hunter.logging import get_logger, set_scan_context
from hunter.api.services.scan_executor import is_scan_process_alive, queue_position, submit_scan
from hunter.orchestration.scan_status import read_scan_status
from hunter.persistence.database import ScanRow, init_db, session_scope
from hunter.persistence.repositories import FindingRepository, ScanRepository
from hunter.settings import HunterSettings

_LOG = get_logger("hunter.api.jobs")
_LOCK = threading.Lock()
_MEMORY: dict[str, dict[str, Any]] = {}


def queue_scan(
    settings: HunterSettings,
    plugin_root: Path,
    *,
    source_type: str,
    source_label: str | None,
    scan_id: str | None = None,
) -> str:
    scan_id = scan_id or uuid.uuid4().hex
    init_db(settings.database_url)
    with _LOCK:
        _MEMORY[scan_id] = {
            "status": "QUEUED",
            "output_dir": None,
            "error": None,
            "progress": "Queued",
            "plugin_slug": plugin_root.resolve().name[:200] or "plugin",
        }
    if settings.database_url:
        try:
            with session_scope() as s:
                import hashlib

                h = hashlib.sha256(str(plugin_root.resolve()).encode()).hexdigest()[:32]
                ScanRepository(s).upsert_scan_start(
                    ScanRow(
                        id=scan_id,
                        plugin_slug=plugin_root.resolve().name[:200] or "plugin",
                        root_path_hash=h,
                        status="QUEUED",
                        source_type=source_type,
                        source_label=source_label,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("scan_queue_db_skipped", error=str(exc))

    try:
        submit_scan(
            plugin_root,
            scan_id,
            source_type=source_type,
            source_label=source_label,
        )
    except Exception as exc:  # noqa: BLE001
        with _LOCK:
            _MEMORY[scan_id] = {
                "status": "FAILED",
                "error": str(exc),
                "progress": "Failed to start scan worker",
                "plugin_slug": plugin_root.resolve().name[:200] or "plugin",
            }
        if settings.database_url:
            try:
                with session_scope() as s:
                    ScanRepository(s).mark_failed(scan_id, str(exc))
            except Exception:  # noqa: BLE001
                pass
        raise
    return scan_id


def _count_findings_file(output_dir: Path) -> int:
    p = output_dir / "reports" / "findings.json"
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return len(data.get("findings", []))
    except Exception:  # noqa: BLE001
        return 0


def _row_to_summary(row: ScanRow) -> ScanSummary:
    return ScanSummary(
        scan_id=row.id,
        plugin_slug=row.plugin_slug,
        status=row.status,
        source_type=row.source_type or "local",
        source_label=row.source_label,
        findings_count=row.findings_count or 0,
        started_at=row.started_at,
        finished_at=row.finished_at,
        snapshot_id=row.snapshot_id,
        error_message=row.error_message,
    )


def _read_report_scan_id(report_path: Path) -> str | None:
    if not report_path.is_file():
        return None
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        return data.get("scan_id")
    except Exception:  # noqa: BLE001
        return None


def _dir_belongs_to_scan(directory: Path, scan_id: str) -> bool:
    """A directory is considered the scan's output_dir if it contains either
    the final findings.json or a live scan-status.json for that scan_id.
    This lets the API surface in-progress status updates before the scan
    has produced any reports."""
    if not directory.is_dir():
        return False
    report = directory / "reports" / "findings.json"
    if report.is_file() and _read_report_scan_id(report) == scan_id:
        return True
    status_path = directory / "scan-status.json"
    if status_path.is_file():
        try:
            data = json.loads(status_path.read_text(encoding="utf-8"))
            return data.get("scan_id") == scan_id
        except Exception:  # noqa: BLE001
            return False
    return False


def resolve_output_dir(
    settings: HunterSettings,
    scan_id: str,
    *,
    plugin_slug: str | None = None,
    output_dir: str | None = None,
) -> Path | None:
    if output_dir:
        p = Path(output_dir)
        if _dir_belongs_to_scan(p, scan_id):
            return p
    with _LOCK:
        mem = _MEMORY.get(scan_id)
        if mem and mem.get("output_dir"):
            p = Path(mem["output_dir"])
            if _dir_belongs_to_scan(p, scan_id):
                return p
    if plugin_slug:
        nested = settings.output_root / plugin_slug / scan_id
        if _dir_belongs_to_scan(nested, scan_id):
            return nested
        legacy = settings.output_root / plugin_slug
        if _dir_belongs_to_scan(legacy, scan_id):
            return legacy
    root = settings.output_root
    if root.is_dir():
        for slug_dir in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not slug_dir.is_dir():
                continue
            nested = slug_dir / scan_id
            if _dir_belongs_to_scan(nested, scan_id):
                return nested
            if _dir_belongs_to_scan(slug_dir, scan_id):
                return slug_dir
            if slug_dir.name == scan_id and _dir_belongs_to_scan(slug_dir, scan_id):
                return slug_dir
    return None


def _repair_stale_running(settings: HunterSettings, detail: ScanDetail) -> ScanDetail:
    """Mark scans stuck RUNNING after API restart once artifacts exist on disk."""
    if detail.status not in ("QUEUED", "RUNNING"):
        return detail
    out = resolve_output_dir(
        settings,
        detail.scan_id,
        plugin_slug=detail.plugin_slug or None,
        output_dir=detail.output_dir,
    )
    if out and (out / "reports" / "findings.json").is_file():
        return _sync_detail_from_disk(settings, detail)
    if detail.started_at:
        age = datetime.now(UTC) - detail.started_at.replace(tzinfo=UTC)
        if age > timedelta(hours=2) and detail.status in ("QUEUED", "RUNNING"):
            return detail.model_copy(
                update={
                    "status": "FAILED",
                    "error_message": detail.error_message or "Scan timed out — delete and try again",
                    "progress": "Timed out",
                }
            )
        if age > timedelta(hours=6):
            return detail.model_copy(
                update={
                    "status": "FAILED",
                    "error_message": detail.error_message or "Scan interrupted or timed out",
                }
            )
    return detail


def _apply_status_file(detail: ScanDetail, out: Path) -> ScanDetail:
    raw = read_scan_status(out)
    if not raw:
        return detail
    updates: dict[str, Any] = {}
    if raw.get("status"):
        updates["status"] = str(raw["status"])
    if raw.get("detail"):
        updates["progress"] = str(raw["detail"])
    elif raw.get("stage"):
        updates["progress"] = str(raw["stage"])
    if raw.get("stage"):
        updates["stage"] = str(raw["stage"])
    if "progress_pct" in raw:
        try:
            updates["progress_pct"] = float(raw["progress_pct"])
        except (TypeError, ValueError):
            pass
    if raw.get("error"):
        updates["error_message"] = str(raw["error"])
    return detail.model_copy(update=updates) if updates else detail


def _sync_detail_from_disk(settings: HunterSettings, detail: ScanDetail) -> ScanDetail:
    out = resolve_output_dir(
        settings,
        detail.scan_id,
        plugin_slug=detail.plugin_slug or None,
        output_dir=detail.output_dir,
    )
    if not out:
        return detail
    detail = _apply_status_file(detail, out)
    count = _count_findings_file(out)
    updates: dict[str, Any] = {
        "output_dir": str(out),
        "findings_count": max(detail.findings_count, count),
    }
    if detail.status in ("QUEUED", "RUNNING") and (out / "reports" / "findings.json").is_file():
        updates["status"] = "COMPLETED"
        if settings.database_url:
            try:
                with session_scope() as s:
                    ScanRepository(s).finish_scan(
                        detail.scan_id,
                        "COMPLETED",
                        detail.snapshot_id,
                        detail.replay_token,
                        output_dir=str(out),
                        findings_count=count,
                    )
            except Exception:  # noqa: BLE001
                pass
    return detail.model_copy(update=updates)


def get_scan_status(settings: HunterSettings, scan_id: str) -> ScanDetail | None:
    with _LOCK:
        mem = _MEMORY.get(scan_id)
    detail: ScanDetail | None = None
    if settings.database_url:
        try:
            with session_scope() as s:
                row = ScanRepository(s).get(scan_id)
                if row:
                    detail = ScanDetail(
                        **_row_to_summary(row).model_dump(),
                        output_dir=row.output_dir,
                        replay_token=row.replay_token,
                    )
        except Exception:  # noqa: BLE001
            pass
    if detail is None and mem:
        detail = ScanDetail(
            scan_id=scan_id,
            plugin_slug=mem.get("plugin_slug") or "",
            status=mem.get("status", "UNKNOWN"),
            findings_count=mem.get("findings_count", 0),
            error_message=mem.get("error"),
            output_dir=mem.get("output_dir"),
        )
    if detail is None:
        return None
    if mem:
        if mem.get("status") in ("QUEUED", "RUNNING", "COMPLETED", "FAILED"):
            if detail.status in ("QUEUED", "RUNNING") or (
                detail.status == "RUNNING" and mem.get("status") == "COMPLETED"
            ):
                detail = detail.model_copy(update={"status": mem["status"]})
        if mem.get("output_dir"):
            detail = detail.model_copy(update={"output_dir": mem["output_dir"]})
        if mem.get("findings_count"):
            detail = detail.model_copy(
                update={"findings_count": max(detail.findings_count, mem["findings_count"])}
            )
        if not detail.plugin_slug and mem.get("plugin_slug"):
            detail = detail.model_copy(update={"plugin_slug": mem["plugin_slug"]})
        if mem.get("progress"):
            detail = detail.model_copy(update={"progress": mem["progress"]})
    detail = _sync_detail_from_disk(settings, detail)
    detail = _repair_stale_running(settings, detail)
    if detail.status in ("QUEUED", "RUNNING"):
        pos = queue_position(scan_id)
        if pos is not None and pos > 0:
            detail = detail.model_copy(
                update={
                    "status": "QUEUED",
                    "stage": "queued",
                    "progress": f"Queued — position {pos} (waiting for current scan to finish)",
                    "progress_pct": detail.progress_pct if detail.progress_pct is not None else 0.0,
                }
            )
        elif pos == 0 and not detail.progress:
            detail = detail.model_copy(
                update={
                    "stage": detail.stage or "starting",
                    "progress": "Starting scan worker…",
                    "progress_pct": detail.progress_pct if detail.progress_pct is not None else 1.0,
                }
            )
        if not detail.progress:
            detail = detail.model_copy(update={"progress": "Analyzing plugin…"})
        if detail.progress_pct is None:
            detail = detail.model_copy(update={"progress_pct": 0.0})
    return detail


def list_scans(settings: HunterSettings, *, limit: int = 50, offset: int = 0) -> list[ScanSummary]:
    if settings.database_url:
        try:
            with session_scope() as s:
                return [_row_to_summary(r) for r in ScanRepository(s).list_scans(limit=limit, offset=offset)]
        except Exception:  # noqa: BLE001
            pass
    with _LOCK:
        items = [
            ScanSummary(
                scan_id=sid,
                plugin_slug="",
                status=v.get("status", "UNKNOWN"),
                findings_count=v.get("findings_count", 0),
                error_message=v.get("error"),
            )
            for sid, v in _MEMORY.items()
        ]
    return items[offset : offset + limit]


def _finding_from_payload(payload: dict[str, Any], enriched: dict | None = None) -> FindingSummary:
    anchors = payload.get("anchors") or []
    loc = anchors[0] if anchors else {}
    conf = (enriched or {}).get("confidence") or {}
    ver = (enriched or {}).get("verification") or {}
    rule_id = payload.get("rule_id", "")
    return FindingSummary(
        finding_id=payload.get("finding_id", ""),
        rule_id=rule_id,
        severity=payload.get("severity_band_static", "INFO"),
        vuln_type=vuln_type_from_rule(rule_id),
        title=title_from_rule(rule_id),
        file_path=loc.get("file_rel_path"),
        start_line=loc.get("start_line"),
        confidence_score=conf.get("score"),
        verification_status=ver.get("status") if isinstance(ver, dict) else None,
    )


def _load_findings_from_disk(output_dir: Path) -> list[dict[str, Any]]:
    report = output_dir / "reports" / "findings.json"
    if not report.exists():
        return []
    data = json.loads(report.read_text(encoding="utf-8"))
    items: list[dict[str, Any]] = []
    for raw in data.get("findings", []):
        cand = raw.get("candidate") or raw
        items.append({"candidate": cand, "enriched": raw})
    return items


def _empty_findings_page(scan_id: str) -> FindingsPage:
    return FindingsPage(
        scan_id=scan_id,
        total=0,
        items=[],
        severity_counts={},
        rule_counts={},
        vuln_type_counts={},
    )


def _vuln_type_counts_from_rules(rule_counts: dict[str, int]) -> dict[str, int]:
    out: dict[str, int] = {}
    for rid, cnt in rule_counts.items():
        vt = vuln_type_from_rule(rid)
        out[vt] = out.get(vt, 0) + cnt
    return out


def get_findings(
    settings: HunterSettings,
    scan_id: str,
    *,
    severity: str | None = None,
    rule_id: str | None = None,
    vuln_type: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> FindingsPage | None:
    detail = get_scan_status(settings, scan_id)
    if not detail:
        return None

    items: list[FindingSummary] = []
    severity_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}

    if settings.database_url:
        try:
            with session_scope() as s:
                fr = FindingRepository(s)
                total = fr.count_for_scan(
                    scan_id, severity=severity, rule_id=rule_id, vuln_type=vuln_type
                )
                rows = fr.list_for_scan(
                    scan_id,
                    severity=severity,
                    rule_id=rule_id,
                    vuln_type=vuln_type,
                    limit=limit,
                    offset=offset,
                )
                severity_counts = fr.severity_counts(scan_id)
                rule_counts = fr.rule_counts(scan_id)
                for row in rows:
                    items.append(_finding_from_payload(row.payload))
                if rows or total:
                    return FindingsPage(
                        scan_id=scan_id,
                        total=total,
                        items=items,
                        severity_counts=severity_counts,
                        rule_counts=rule_counts,
                        vuln_type_counts=_vuln_type_counts_from_rules(rule_counts),
                    )
        except Exception:  # noqa: BLE001
            pass

    out = resolve_output_dir(
        settings,
        scan_id,
        plugin_slug=detail.plugin_slug or None,
        output_dir=detail.output_dir,
    )
    if not out:
        if detail.status in ("QUEUED", "RUNNING"):
            return _empty_findings_page(scan_id)
        return _empty_findings_page(scan_id)

    raw_items = _load_findings_from_disk(out)
    vuln_type_counts: dict[str, int] = {}
    for entry in raw_items:
        cand = entry["candidate"]
        f = _finding_from_payload(cand, entry.get("enriched"))
        # Always tally the unfiltered totals so charts reflect the whole scan
        # even when the table is filtered to a single severity / vuln type.
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1
        vuln_type_counts[f.vuln_type] = vuln_type_counts.get(f.vuln_type, 0) + 1
        if severity and f.severity.upper() != severity.upper():
            continue
        if rule_id and f.rule_id != rule_id:
            continue
        if vuln_type and f.vuln_type.upper() != vuln_type.upper():
            continue
        items.append(f)
    total = len(items)
    page = items[offset : offset + limit]
    return FindingsPage(
        scan_id=scan_id,
        total=total,
        items=page,
        severity_counts=severity_counts,
        rule_counts=rule_counts,
        vuln_type_counts=vuln_type_counts,
    )


def aggregate_stats(settings: HunterSettings) -> dict[str, int]:
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    if not settings.database_url:
        return {"total_scans": len(_MEMORY), "by_severity": by_severity, "by_vuln_type": by_type}
    try:
        with session_scope() as s:
            scans = ScanRepository(s).list_scans(limit=500)
            for sc in scans:
                fr = FindingRepository(s)
                for sev, cnt in fr.severity_counts(sc.id).items():
                    by_severity[sev] = by_severity.get(sev, 0) + cnt
                for rid, cnt in fr.rule_counts(sc.id).items():
                    vt = vuln_type_from_rule(rid)
                    by_type[vt] = by_type.get(vt, 0) + cnt
            return {
                "total_scans": ScanRepository(s).count_scans(),
                "by_severity": by_severity,
                "by_vuln_type": by_type,
            }
    except Exception:  # noqa: BLE001
        return {"total_scans": 0, "by_severity": by_severity, "by_vuln_type": by_type}


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _safe_rmtree(path: Path, allowed_root: Path) -> bool:
    if not path.exists():
        return False
    if not _is_under(path, allowed_root):
        _LOG.warning("delete_path_rejected", path=str(path), root=str(allowed_root))
        return False
    try:
        shutil.rmtree(path)
        return True
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("delete_path_failed", path=str(path), error=str(exc))
        return False


def _artifact_paths(settings: HunterSettings, scan_id: str, detail: ScanDetail | None) -> list[Path]:
    paths: list[Path] = []
    upload_dir = settings.workspace_root / "uploads" / scan_id
    if upload_dir.is_dir():
        paths.append(upload_dir)
    if detail:
        out = resolve_output_dir(
            settings,
            scan_id,
            plugin_slug=detail.plugin_slug or None,
            output_dir=detail.output_dir,
        )
        if out:
            paths.append(out)
    github_root = settings.workspace_root / "github"
    if github_root.is_dir():
        prefix = scan_id[:12]
        for candidate in github_root.rglob(prefix):
            if candidate.is_dir() and _is_under(candidate, github_root):
                paths.append(candidate)
    return paths


def reconcile_stale_scans(settings: HunterSettings) -> int:
    """Mark DB scans stuck RUNNING with no live status file as FAILED after API restart."""
    if not settings.database_url:
        return 0
    n = 0
    try:
        with session_scope() as s:
            for row in ScanRepository(s).list_scans(limit=500):
                if row.status not in ("QUEUED", "RUNNING"):
                    continue
                out = resolve_output_dir(settings, row.id, plugin_slug=row.plugin_slug, output_dir=row.output_dir)
                if out:
                    st = read_scan_status(out)
                    if st and st.get("status") == "COMPLETED":
                        continue
                ScanRepository(s).mark_failed(row.id, "Scan interrupted (API restarted). Delete and run again.")
                n += 1
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("reconcile_stale_skipped", error=str(exc))
    return n


def delete_scan(settings: HunterSettings, scan_id: str, *, delete_artifacts: bool = True) -> bool:
    detail = get_scan_status(settings, scan_id)
    with _LOCK:
        in_memory = scan_id in _MEMORY
    if detail is None and not in_memory:
        return False
    paths = _artifact_paths(settings, scan_id, detail)
    with _LOCK:
        _MEMORY.pop(scan_id, None)
    deleted_db = False
    if settings.database_url:
        try:
            with session_scope() as s:
                deleted_db = ScanRepository(s).delete_scan(scan_id)
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("delete_scan_db_failed", scan_id=scan_id, error=str(exc))
    if delete_artifacts:
        for path in paths:
            if _is_under(path, settings.output_root):
                _safe_rmtree(path, settings.output_root)
            elif _is_under(path, settings.workspace_root):
                _safe_rmtree(path, settings.workspace_root)
    _LOG.info("scan_deleted", scan_id=scan_id, artifacts=delete_artifacts)
    return True
