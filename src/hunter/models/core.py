from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class SnapshotMode(StrEnum):
    copy = "copy"
    manifest_only = "manifest-only"


class IngestStatus(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ScanStage(StrEnum):
    ingest = "ingest"
    parse = "parse"
    graph = "graph"
    wp_semantics = "wp_semantics"
    taint = "taint"
    analysis = "analysis"
    verify_static = "verify_static"
    agents = "agents"
    confidence = "confidence"
    reporting = "reporting"


class QuotaConfig(BaseModel):
    max_files: int = 50_000
    max_total_bytes: int = 5 * 1024**3
    max_single_file_bytes: int = 50 * 1024**2
    max_depth: int = 64
    follow_symlinks: bool = False


class RepoManifestFile(BaseModel):
    rel_path: str
    abs_path_norm: str
    sha256: str
    size: int
    mtime_ns: int | None = None
    language_guess: Literal["php", "javascript", "html", "other", "binary"] = "other"
    encoding: str = "utf-8"
    parse_policy: Literal["parse", "skip_binary", "skip_size", "skip_encoding"] = "parse"


class RepoManifest(BaseModel):
    model_config = {"frozen": True}

    root_path_norm: str
    files: tuple[RepoManifestFile, ...] = Field(default_factory=tuple)
    manifest_sha256: str = ""


class IngestDiagnostic(BaseModel):
    path: str
    code: str
    message: str


class IngestResult(BaseModel):
    status: IngestStatus
    manifest: RepoManifest
    diagnostics: list[IngestDiagnostic] = Field(default_factory=list)
    stopped_at_path: str | None = None
    tree_sha256: str = ""


class ScanResources(BaseModel):
    cpu_count: int
    ram_gb: int
    workers: int
    max_inflight: int


class DeterminismMeta(BaseModel):
    replay_token: str
    manifest_sha256: str
    parser_lock_hash: str
    graph_schema_version: str
    rule_pack_hash: str
    hunter_version: str
    agents_disabled: bool
    llm_model_id: str = ""
    scan_profile: str = ""
    catalog_hash: str = ""


class ScanProfile(BaseModel):
    """Resolved scan profile: catalogs, adapters, and rule pack."""

    profile_id: str
    catalog_ids: list[str] = Field(default_factory=list)
    adapter_ids: list[str] = Field(default_factory=list)
    rule_pack_path: Path


class ScanConfig(BaseModel):
    plugin_root: Path
    profile: str = "auto"
    output_root: Path = Field(default=Path("output"))
    snapshot_mode: SnapshotMode = SnapshotMode.copy
    quotas: QuotaConfig = Field(default_factory=QuotaConfig)
    scan_id: str = ""
    trace_id: str = ""
    agents_enabled: bool = False
    neo4j_uri: str = ""
    neo4j_user: str = ""
    neo4j_password: str = ""
    database_url: str = ""
    rule_pack_path: Path | None = None
    graph_schema_version: str = "3"
    rule_timeout_seconds: float = 60.0
    semantic_ir_v2_enabled: bool = False
    resolver_interprocedural_enabled: bool = False
    cfg_ssa_enabled: bool = False
    taint_path_sensitive_enabled: bool = False
    wp_semantics_v2_enabled: bool = False  # deprecated: use profile adapters
    resolved_profile: ScanProfile | None = None
    security_popchain_enabled: bool = False
    semantic_diff_enabled: bool = False
    incremental_recompute_enabled: bool = False
    neo4j_layered_write_enabled: bool = False
    scan_workers: int = 0
    scan_max_inflight: int = 0
    dashboard_meta: dict[str, str] = Field(default_factory=dict)
    persist_findings_to_db: bool = True


class ScanResult(BaseModel):
    scan_id: str
    plugin_slug: str
    output_dir: Path
    snapshot_id: str
    stages_completed: list[ScanStage] = Field(default_factory=list)
    ingest: IngestResult | None = None
    determinism: DeterminismMeta | None = None
    graph_integrity_ok: bool = True
    errors: list[str] = Field(default_factory=list)
