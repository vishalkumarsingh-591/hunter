from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from hunter.logging import configure_logging, set_scan_context
from hunter.orchestration.scan_runner import ScanRunner
from hunter.settings import HunterSettings

app = FastAPI(title="Hunter", version="0.1.0")
_settings: HunterSettings | None = None


def get_settings() -> HunterSettings:
    global _settings
    if _settings is None:
        _settings = HunterSettings.load()
        configure_logging(_settings.log_level, json_logs=True)
    return _settings


class ScanRequest(BaseModel):
    plugin_path: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    output_dir: str | None = None
    snapshot_id: str | None = None


_STORE: dict[str, ScanResponse] = {}


@app.post("/scans", response_model=ScanResponse)
def create_scan(body: ScanRequest) -> ScanResponse:
    p = Path(body.plugin_path)
    if not p.is_dir():
        raise HTTPException(400, "plugin_path must be a directory")
    scan_id = uuid.uuid4().hex
    set_scan_context(scan_id=scan_id, trace_id=scan_id)
    settings = get_settings()
    from hunter.models.core import QuotaConfig, ScanConfig

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
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password,
        database_url=settings.database_url,
        rule_pack_path=settings.rule_pack_path,
        graph_schema_version=settings.graph_schema_version,
    )
    runner = ScanRunner(settings)
    result = runner.run(cfg)
    resp = ScanResponse(
        scan_id=result.scan_id,
        status="COMPLETED",
        output_dir=str(result.output_dir),
        snapshot_id=result.snapshot_id,
    )
    _STORE[result.scan_id] = resp
    return resp


@app.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str) -> ScanResponse:
    if scan_id not in _STORE:
        raise HTTPException(404, "unknown scan_id")
    return _STORE[scan_id]
