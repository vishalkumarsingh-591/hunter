from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from hunter.api.deps import get_settings
from hunter.api.schemas import JobResponse, UploadResponse
from hunter.api.services.scan_jobs import queue_scan
from hunter.api.services.workspace import extract_upload, save_folder_files, save_upload_stream

router = APIRouter(prefix="/api/uploads", tags=["uploads"])

_MAX_BYTES = 512 * 1024 * 1024


@router.post("", response_model=JobResponse)
async def api_upload_and_scan(file: UploadFile = File(...)) -> JobResponse:
    if not file.filename:
        raise HTTPException(400, "Missing filename")
    settings = get_settings()
    scan_id = uuid.uuid4().hex
    upload_dir = settings.workspace_root / "uploads" / scan_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest_file = upload_dir / Path(file.filename).name
    size = 0
    chunks: list[bytes] = []

    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > _MAX_BYTES:
            raise HTTPException(413, "Upload exceeds 512 MiB limit")
        chunks.append(chunk)

    save_upload_stream(dest_file, chunks)
    extract_dir = upload_dir / "extracted"
    try:
        plugin_root = extract_upload(dest_file, extract_dir)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Could not extract upload: {exc}") from exc

    label = file.filename
    queue_scan(
        settings,
        plugin_root,
        source_type="upload",
        source_label=label,
        scan_id=scan_id,
    )
    return JobResponse(scan_id=scan_id, status="QUEUED", message=f"Uploaded {label}; scan started")


@router.post("/folder", response_model=JobResponse)
async def api_upload_folder(files: list[UploadFile] = File(...)) -> JobResponse:
    if not files:
        raise HTTPException(400, "No files in folder upload")
    settings = get_settings()
    scan_id = uuid.uuid4().hex
    extract_dir = settings.workspace_root / "uploads" / scan_id / "extracted"
    total = 0
    batch: list[tuple[str, bytes]] = []
    label = "folder"
    for uf in files:
        if not uf.filename:
            continue
        rel = uf.filename.replace("\\", "/")
        if "/" in rel:
            label = rel.split("/")[0]
        data = await uf.read()
        total += len(data)
        if total > _MAX_BYTES:
            raise HTTPException(413, "Upload exceeds 512 MiB limit")
        batch.append((rel, data))
    try:
        plugin_root = save_folder_files(extract_dir, batch)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Could not store folder: {exc}") from exc
    queue_scan(
        settings,
        plugin_root,
        source_type="upload",
        source_label=label,
        scan_id=scan_id,
    )
    return JobResponse(scan_id=scan_id, status="QUEUED", message=f"Uploaded folder {label}; scan started")


@router.post("/prepare", response_model=UploadResponse)
async def api_upload_only(file: UploadFile = File(...)) -> UploadResponse:
    """Store upload without starting scan (optional workflow)."""
    if not file.filename:
        raise HTTPException(400, "Missing filename")
    settings = get_settings()
    scan_id = uuid.uuid4().hex
    upload_dir = settings.workspace_root / "uploads" / scan_id
    dest_file = upload_dir / Path(file.filename).name
    size = 0
    chunks: list[bytes] = []
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > _MAX_BYTES:
            raise HTTPException(413, "Upload exceeds 512 MiB limit")
        chunks.append(chunk)
    save_upload_stream(dest_file, chunks)
    extract_dir = upload_dir / "extracted"
    plugin_root = extract_upload(dest_file, extract_dir)
    return UploadResponse(
        scan_id=scan_id,
        status="READY",
        workspace_path=str(plugin_root),
        label=file.filename,
    )
