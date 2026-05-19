from __future__ import annotations

import os
import subprocess
import sys
import threading
from collections import deque
from pathlib import Path
from typing import Any

from hunter.logging import get_logger

_LOG = get_logger("hunter.api.executor")
_PROCS: dict[str, subprocess.Popen[Any]] = {}
_QUEUE: deque[tuple[Path, str, str, str | None]] = deque()
_LOCK = threading.Lock()
_WORKER_THREAD: threading.Thread | None = None


def _worker_log_path(scan_id: str) -> Path:
    log_dir = Path("workspaces") / "logs" / "scans"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / f"{scan_id}.log"


def _spawn(plugin_root: Path, scan_id: str, source_type: str, source_label: str | None) -> subprocess.Popen[Any]:
    cmd = [
        sys.executable,
        "-m",
        "hunter.api.services.scan_worker",
        scan_id,
        str(plugin_root.resolve()),
        source_type,
        source_label or "",
    ]
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    log_file = _worker_log_path(scan_id)
    fh = open(log_file, "ab", buffering=0)
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    proc = subprocess.Popen(
        cmd,
        cwd=str(Path.cwd()),
        creationflags=creationflags,
        stdout=fh,
        stderr=fh,
        env=env,
        close_fds=True,
    )
    fh.close()  # subprocess keeps its own handle
    _LOG.info("scan_subprocess_started", scan_id=scan_id, pid=proc.pid, log=str(log_file))
    return proc


def _drain_queue() -> None:
    while True:
        with _LOCK:
            if not _QUEUE:
                return
            plugin_root, scan_id, source_type, source_label = _QUEUE.popleft()
        try:
            proc = _spawn(plugin_root, scan_id, source_type, source_label)
            with _LOCK:
                _PROCS[scan_id] = proc
            proc.wait()
            _LOG.info("scan_subprocess_finished", scan_id=scan_id, exit=proc.returncode)
        except Exception as exc:  # noqa: BLE001
            _LOG.exception("scan_subprocess_failed", scan_id=scan_id, error=str(exc))
        finally:
            with _LOCK:
                _PROCS.pop(scan_id, None)


def _ensure_worker_thread() -> None:
    global _WORKER_THREAD
    if _WORKER_THREAD is None or not _WORKER_THREAD.is_alive():
        _WORKER_THREAD = threading.Thread(target=_drain_queue, daemon=True, name="hunter-scan-dispatcher")
        _WORKER_THREAD.start()


def submit_scan(
    plugin_root: Path,
    scan_id: str,
    *,
    source_type: str,
    source_label: str | None,
) -> None:
    """Queue a scan; one scan runs at a time to avoid CPU thrash on Windows."""
    with _LOCK:
        _QUEUE.append((plugin_root, scan_id, source_type, source_label))
    _ensure_worker_thread()


def is_scan_process_alive(scan_id: str) -> bool:
    with _LOCK:
        proc = _PROCS.get(scan_id)
    if proc is None:
        return False
    return proc.poll() is None


def queue_position(scan_id: str) -> int | None:
    """0 = running, 1+ = queue position. None when unknown."""
    with _LOCK:
        if scan_id in _PROCS:
            return 0
        for i, (_, sid, _, _) in enumerate(_QUEUE):
            if sid == scan_id:
                return i + 1
    return None
