from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from hunter.api.deps import get_settings
from hunter.api.routers import github, scans, uploads

app = FastAPI(
    title="Hunter Security Dashboard",
    version="0.2.0",
    description="Connect GitHub repos or upload code to run Hunter static analysis.",
)

_settings = None


@app.on_event("startup")
def _startup() -> None:
    global _settings
    _settings = get_settings()
    _settings.workspace_root.mkdir(parents=True, exist_ok=True)
    _settings.output_root.mkdir(parents=True, exist_ok=True)
    _settings.parse_cache_root.mkdir(parents=True, exist_ok=True)
    from hunter.api.services.scan_jobs import reconcile_stale_scans

    reconcile_stale_scans(_settings)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "hunter-dashboard"}


def _cors_origins() -> list[str]:
    try:
        return get_settings().cors_origins
    except Exception:  # noqa: BLE001
        return ["http://localhost:5173", "http://127.0.0.1:5173"]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(github.router)
app.include_router(uploads.router)

# Legacy minimal scan API (path on server)
from pydantic import BaseModel  # noqa: E402

from hunter.logging import configure_logging, set_scan_context  # noqa: E402
from hunter.orchestration.scan_runner import ScanRunner  # noqa: E402
from hunter.models.core import QuotaConfig, ScanConfig  # noqa: E402
import uuid  # noqa: E402


class ScanRequest(BaseModel):
    plugin_path: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    output_dir: str | None = None
    snapshot_id: str | None = None


@app.post("/scans", response_model=ScanResponse, tags=["legacy"])
def create_scan_sync(body: ScanRequest) -> ScanResponse:
    """Synchronous scan (blocks until complete). Prefer /api/uploads or /api/github/clone."""
    from fastapi import HTTPException

    p = Path(body.plugin_path)
    if not p.is_dir():
        raise HTTPException(400, "plugin_path must be a directory")
    settings = get_settings()
    scan_id = uuid.uuid4().hex
    set_scan_context(scan_id=scan_id, trace_id=scan_id)
    cfg = ScanConfig(
        plugin_root=p,
        output_root=settings.output_root,
        scan_id=scan_id,
        trace_id=scan_id,
        quotas=QuotaConfig(
            max_files=settings.ingest_max_files,
            max_total_bytes=settings.ingest_max_total_bytes,
            max_single_file_bytes=settings.ingest_max_single_file_bytes,
            max_depth=settings.ingest_max_depth,
            follow_symlinks=settings.ingest_follow_symlinks,
        ),
        agents_enabled=settings.agents_enabled,
        database_url=settings.database_url,
        rule_pack_path=settings.rule_pack_path,
        graph_schema_version=settings.graph_schema_version,
    )
    result = ScanRunner(settings).run(cfg)
    return ScanResponse(
        scan_id=result.scan_id,
        status="COMPLETED",
        output_dir=str(result.output_dir),
        snapshot_id=result.snapshot_id,
    )


_dashboard_dist = Path(__file__).resolve().parents[3] / "dashboard" / "dist"
if _dashboard_dist.is_dir():
    app.mount("/", StaticFiles(directory=str(_dashboard_dist), html=True), name="dashboard")
