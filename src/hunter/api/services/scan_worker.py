"""Isolated scan worker — run as subprocess so API reload does not kill scans."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from hunter.logging import configure_logging, set_scan_context
from hunter.models.core import QuotaConfig, ScanConfig
from hunter.orchestration.scan_runner import ScanRunner
from hunter.orchestration.scan_status import write_scan_status
from hunter.persistence.database import init_db, session_scope
from hunter.persistence.repositories import ScanRepository
from hunter.settings import HunterSettings


def _bail_out(settings: HunterSettings, scan_id: str, message: str, plugin_root: Path | None = None) -> None:
    """Write FAILED status to disk and DB before exiting non-zero."""
    try:
        if plugin_root is not None:
            slug = plugin_root.name[:200] or "plugin"
        else:
            slug = "plugin"
        out = (settings.output_root / slug / scan_id).resolve()
        out.mkdir(parents=True, exist_ok=True)
        write_scan_status(
            out,
            scan_id=scan_id,
            status="FAILED",
            stage="failed",
            detail=message[:300],
            error=message,
        )
    except Exception:  # noqa: BLE001
        pass
    try:
        with session_scope() as s:
            ScanRepository(s).mark_failed(scan_id, message)
    except Exception:  # noqa: BLE001
        pass


def _resolve_settings() -> HunterSettings:
    settings = HunterSettings.load()
    # Match the API's SQLite fallback so the worker writes to the same DB.
    if not settings.database_url:
        data_dir = settings.workspace_root / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        db_path = data_dir / "hunter.db"
        settings = settings.model_copy(update={"database_url": f"sqlite:///{db_path.as_posix()}"})
    return settings


def _count_php_files(root: Path, cap: int = 3) -> int:
    """Cheap probe — returns up to `cap` to short-circuit on huge plugins."""
    n = 0
    if not root.exists():
        return 0
    try:
        for _ in root.rglob("*.php"):
            n += 1
            if n >= cap:
                break
    except OSError:
        pass
    return n


def run_dashboard_scan(
    plugin_root: Path,
    scan_id: str,
    *,
    source_type: str,
    source_label: str | None,
) -> None:
    settings = _resolve_settings()
    configure_logging(settings.log_level, json_logs=True)
    set_scan_context(scan_id=scan_id, trace_id=scan_id)
    init_db(settings.database_url)
    plugin_root = plugin_root.resolve()
    if not plugin_root.exists() or not plugin_root.is_dir():
        msg = f"Source folder not found: {plugin_root}"
        _bail_out(settings, scan_id, msg)
        raise SystemExit(1)
    if _count_php_files(plugin_root) == 0:
        msg = (
            "No PHP files found in the uploaded source. "
            "Make sure your zip contains a WordPress plugin/theme (PHP files)."
        )
        _bail_out(settings, scan_id, msg, plugin_root=plugin_root)
        raise SystemExit(2)
    fast = settings.dashboard_fast_scan
    if fast:
        # Fast scan profile: skip heavy IR lifting and structure-complete mode so large plugins
        # finish in seconds instead of minutes. Rules still run against tree-sitter parse output.
        settings = settings.model_copy(
            update={
                "lift_version": "1",
                "parse_structure_complete_mode": False,
                "parse_max_ir_nodes_per_file": min(settings.parse_max_ir_nodes_per_file, 80_000),
                "parse_per_file_timeout_seconds": min(settings.parse_per_file_timeout_seconds, 20.0),
            }
        )
    slug = plugin_root.resolve().name[:200] or "plugin"
    out = (settings.output_root / slug / scan_id).resolve()
    out.mkdir(parents=True, exist_ok=True)
    write_scan_status(
        out,
        scan_id=scan_id,
        status="RUNNING",
        stage="starting",
        detail="Initializing scan…",
        progress_pct=2,
    )

    cfg = ScanConfig(
        plugin_root=plugin_root.resolve(),
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
        agents_enabled=False,
        database_url=settings.database_url,
        rule_pack_path=settings.rule_pack_path,
        graph_schema_version=settings.graph_schema_version,
        rule_timeout_seconds=settings.rule_timeout_seconds,
        semantic_ir_v2_enabled=settings.semantic_ir_v2_enabled and not fast,
        resolver_interprocedural_enabled=settings.resolver_interprocedural_enabled and not fast,
        cfg_ssa_enabled=settings.cfg_ssa_enabled and not fast,
        taint_path_sensitive_enabled=settings.taint_path_sensitive_enabled and not fast,
        wp_semantics_v2_enabled=settings.wp_semantics_v2_enabled and not fast,
        security_popchain_enabled=settings.security_popchain_enabled and not fast,
        persist_findings_to_db=settings.dashboard_persist_findings,
        dashboard_meta={"source_type": source_type, "source_label": source_label or ""},
    )
    try:
        ScanRunner(settings).run(cfg)
    except Exception as exc:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        try:
            write_scan_status(
                out,
                scan_id=scan_id,
                status="FAILED",
                stage="failed",
                detail=str(exc)[:300],
                error=str(exc),
            )
        except Exception:  # noqa: BLE001
            pass
        try:
            with session_scope() as s:
                ScanRepository(s).mark_failed(scan_id, str(exc))
        except Exception:  # noqa: BLE001
            pass
        raise SystemExit(1) from exc


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) < 2:
        print("usage: scan_worker <scan_id> <plugin_root> [source_type] [source_label]", file=sys.stderr)
        return 2
    scan_id, plugin_root, *rest = args
    source_type = rest[0] if len(rest) > 0 else "upload"
    source_label = rest[1] if len(rest) > 1 else None
    run_dashboard_scan(Path(plugin_root), scan_id, source_type=source_type, source_label=source_label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
