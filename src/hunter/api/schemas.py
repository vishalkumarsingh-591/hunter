from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class ScanSummary(BaseModel):
    scan_id: str
    plugin_slug: str
    status: str
    source_type: str = "local"
    source_label: str | None = None
    findings_count: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    snapshot_id: str | None = None
    error_message: str | None = None
    progress: str | None = None
    progress_pct: float | None = None
    stage: str | None = None


class ScanDetail(ScanSummary):
    output_dir: str | None = None
    replay_token: str | None = None


class FindingSummary(BaseModel):
    finding_id: str
    rule_id: str
    severity: str
    vuln_type: str
    title: str
    file_path: str | None = None
    start_line: int | None = None
    confidence_score: float | None = None
    verification_status: str | None = None


class FindingsPage(BaseModel):
    scan_id: str
    total: int
    items: list[FindingSummary]
    severity_counts: dict[str, int] = Field(default_factory=dict)
    rule_counts: dict[str, int] = Field(default_factory=dict)
    vuln_type_counts: dict[str, int] = Field(default_factory=dict)


class ScanStats(BaseModel):
    total_scans: int
    by_severity: dict[str, int]
    by_vuln_type: dict[str, int]


class GitHubRepo(BaseModel):
    full_name: str
    name: str
    private: bool
    default_branch: str
    html_url: str
    description: str | None = None


class GitHubCloneRequest(BaseModel):
    owner: str
    repo: str
    ref: str | None = None


class GitHubUrlCloneRequest(BaseModel):
    url: str
    ref: str | None = None


class LocalScanRequest(BaseModel):
    plugin_path: str


class UploadResponse(BaseModel):
    scan_id: str
    status: str
    workspace_path: str
    label: str


class JobResponse(BaseModel):
    scan_id: str
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED"]
    message: str | None = None


class DeleteScanResponse(BaseModel):
    scan_id: str
    deleted: bool
    message: str
