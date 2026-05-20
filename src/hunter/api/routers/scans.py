from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from hunter.api.deps import get_settings
from hunter.api.schemas import (
    DeleteScanResponse,
    FindingsPage,
    JobResponse,
    LocalScanRequest,
    ScanDetail,
    ScanStats,
    ScanSummary,
)
from hunter.api.services.scan_jobs import (
    aggregate_stats,
    delete_scan,
    get_findings,
    get_scan_status,
    list_scans,
    queue_scan,
)

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("", response_model=list[ScanSummary])
def api_list_scans(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> list[ScanSummary]:
    return list_scans(get_settings(), limit=limit, offset=offset)


@router.get("/stats/overview", response_model=ScanStats)
def api_scan_stats() -> ScanStats:
    raw = aggregate_stats(get_settings())
    return ScanStats(
        total_scans=raw["total_scans"],
        by_severity=raw["by_severity"],
        by_vuln_type=raw["by_vuln_type"],
    )


@router.delete("/{scan_id}", response_model=DeleteScanResponse)
def api_delete_scan(
    scan_id: str,
    delete_artifacts: bool = Query(True, description="Remove output files and upload workspace"),
) -> DeleteScanResponse:
    if delete_scan(get_settings(), scan_id, delete_artifacts=delete_artifacts):
        return DeleteScanResponse(
            scan_id=scan_id,
            deleted=True,
            message="Scan and artifacts removed",
        )
    raise HTTPException(404, "Scan not found")


@router.get("/{scan_id}", response_model=ScanDetail)
def api_get_scan(scan_id: str) -> ScanDetail:
    detail = get_scan_status(get_settings(), scan_id)
    if not detail:
        raise HTTPException(404, "Scan not found")
    return detail


@router.get("/{scan_id}/findings", response_model=FindingsPage)
def api_scan_findings(
    scan_id: str,
    severity: str | None = None,
    rule_id: str | None = None,
    vuln_type: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> FindingsPage:
    page = get_findings(
        get_settings(),
        scan_id,
        severity=severity,
        rule_id=rule_id,
        vuln_type=vuln_type,
        limit=limit,
        offset=offset,
    )
    if page is None:
        raise HTTPException(404, "Scan or findings not found")
    return page


@router.post("/local", response_model=JobResponse)
def api_scan_local(body: LocalScanRequest) -> JobResponse:
    p = Path(body.plugin_path)
    if not p.is_dir():
        raise HTTPException(400, "plugin_path must be an existing directory")
    settings = get_settings()
    scan_id = queue_scan(
        settings,
        p.resolve(),
        source_type="local",
        source_label=str(p.resolve()),
    )
    return JobResponse(scan_id=scan_id, status="QUEUED", message="Scan started")
