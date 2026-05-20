from __future__ import annotations

import uuid

from fastapi import APIRouter, Header, HTTPException

from hunter.api.deps import get_settings
from hunter.api.schemas import GitHubCloneRequest, GitHubRepo, GitHubUrlCloneRequest, JobResponse
from hunter.api.services import github_client
from hunter.api.services.scan_jobs import queue_scan

router = APIRouter(prefix="/api/github", tags=["github"])


def _token(header: str | None) -> str:
    settings = get_settings()
    return (header or "").strip() or settings.github_token


@router.get("/repos", response_model=list[GitHubRepo])
def api_list_repos(x_github_token: str | None = Header(default=None, alias="X-GitHub-Token")) -> list[GitHubRepo]:
    try:
        return github_client.list_repos(_token(x_github_token))
    except github_client.GitHubError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/clone", response_model=JobResponse)
def api_clone_and_scan(
    body: GitHubCloneRequest,
    x_github_token: str | None = Header(default=None, alias="X-GitHub-Token"),
) -> JobResponse:
    settings = get_settings()
    token = _token(x_github_token)
    scan_id = uuid.uuid4().hex
    dest = settings.workspace_root / "github" / body.owner / body.repo / scan_id
    try:
        root = github_client.clone_repo(
            token=token or None,
            owner=body.owner,
            repo=body.repo,
            dest=dest,
            ref=body.ref,
        )
    except github_client.GitHubError as exc:
        raise HTTPException(400, str(exc)) from exc
    label = f"{body.owner}/{body.repo}"
    queue_scan(settings, root, source_type="github", source_label=label, scan_id=scan_id)
    return JobResponse(scan_id=scan_id, status="QUEUED", message=f"Cloned {label}; scan started")


@router.post("/clone-url", response_model=JobResponse)
def api_clone_url_and_scan(
    body: GitHubUrlCloneRequest,
    x_github_token: str | None = Header(default=None, alias="X-GitHub-Token"),
) -> JobResponse:
    settings = get_settings()
    token = _token(x_github_token) or None
    scan_id = uuid.uuid4().hex
    try:
        root, label = github_client.clone_from_url(
            repo_url=body.url,
            workspace=settings.workspace_root,
            token=token,
            ref=body.ref,
            scan_id=scan_id[:12],
        )
    except github_client.GitHubError as exc:
        raise HTTPException(400, str(exc)) from exc
    queue_scan(settings, root, source_type="github", source_label=label, scan_id=scan_id)
    return JobResponse(scan_id=scan_id, status="QUEUED", message=f"Cloned {label}; scan started")
