from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from hunter import __version__


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class HunterSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HUNTER_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    output_root: Path = Field(default=Path("output"))
    workspace_root: Path = Field(default=Path("workspaces"))
    parse_cache_root: Path = Field(default=Path("workspaces/cache/parse"))
    github_token: str = ""
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"])
    dashboard_persist_findings: bool = False
    dashboard_fast_scan: bool = True
    snapshot_mode: str = Field(default="copy")
    ingest_max_files: int = 50_000
    ingest_max_total_bytes: int = 5 * 1024**3
    ingest_max_single_file_bytes: int = 50 * 1024**2
    ingest_max_depth: int = 64
    ingest_follow_symlinks: bool = False
    parse_per_file_timeout_seconds: float = 120.0
    lift_version: str = "2"
    parse_structure_complete_mode: bool = True
    parse_max_ir_nodes_per_file: int = 250_000
    graph_schema_version: str = "3.1"
    scan_profile: str = "auto"
    scan_workers: int = 0
    scan_max_inflight: int = 0
    graph_batch_size: int = 500
    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    database_url: str = ""
    rule_pack_path: Path | None = None
    rule_timeout_seconds: float = 60.0
    analysis_max_same_file_flow_edges_per_file: int = 500
    taint_max_function_nodes: int = 5000
    taint_max_edges_per_function: int = 50_000
    taint_max_interprocedural_flow_edges: int = 5_000
    taint_worklist_steps: int = 200_000
    regex_taint_fallback_enabled: bool = False
    agents_enabled: bool = False
    agents_max_tool_calls: int = 32
    llm_model: str = ""
    semantic_ir_v2_enabled: bool = False
    resolver_interprocedural_enabled: bool = False
    cfg_ssa_enabled: bool = False
    taint_path_sensitive_enabled: bool = False
    wp_semantics_v2_enabled: bool = False
    security_popchain_enabled: bool = False
    semantic_diff_enabled: bool = False
    incremental_recompute_enabled: bool = False
    neo4j_layered_write_enabled: bool = False
    semantic_max_functions: int = 20_000
    semantic_max_cfg_blocks: int = 250_000
    confidence_weights_path: Path | None = None
    otel_enabled: bool = False
    log_level: str = "INFO"
    reporting_summary_grouped: bool = True
    reporting_summary_min_confidence: float = 0.0
    reporting_summary_exclude_rules: list[str] = Field(default_factory=list)
    reporting_summary_max_groups: int = 500
    reporting_summary_include_blocked: bool = False
    reporting_summary_triage_min_bucket: str = "MEDIUM"

    @classmethod
    def load(cls, yaml_path: Path | None = None) -> HunterSettings:
        defaults: dict[str, Any] = {}
        paths = []
        if yaml_path:
            paths.append(yaml_path)
        root = Path(__file__).resolve().parents[2] / "config" / "default.yaml"
        if root.exists():
            paths.append(root)
        for p in paths:
            with open(p, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            defaults = _deep_merge(defaults, raw)
        flat: dict[str, Any] = {}
        if "output" in defaults:
            flat["output_root"] = Path(defaults["output"].get("root", "./output"))
            flat["snapshot_mode"] = defaults["output"].get("snapshot_mode", "copy")
        if "dashboard" in defaults:
            d = defaults["dashboard"]
            flat["workspace_root"] = Path(d.get("workspace_root", "./workspaces"))
            flat["github_token"] = str(d.get("github_token") or "")
            flat["cors_origins"] = list(d.get("cors_origins") or ["http://localhost:5173", "http://127.0.0.1:5173"])
            flat["dashboard_persist_findings"] = bool(d.get("persist_findings", False))
            flat["dashboard_fast_scan"] = bool(d.get("fast_scan", True))
            pcr = d.get("parse_cache_root") or ""
            if pcr:
                flat["parse_cache_root"] = Path(pcr)
        if "ingest" in defaults:
            ing = defaults["ingest"]
            flat["ingest_max_files"] = ing.get("max_files", 50_000)
            flat["ingest_max_total_bytes"] = ing.get("max_total_bytes", 5 * 1024**3)
            flat["ingest_max_single_file_bytes"] = ing.get("max_single_file_bytes", 50 * 1024**2)
            flat["ingest_max_depth"] = ing.get("max_depth", 64)
            flat["ingest_follow_symlinks"] = ing.get("follow_symlinks", False)
        if "parse" in defaults:
            p = defaults["parse"]
            flat["parse_per_file_timeout_seconds"] = float(p.get("per_file_timeout_seconds", 120))
            flat["lift_version"] = str(p.get("lift_version", "2"))
            flat["parse_structure_complete_mode"] = bool(p.get("structure_complete_mode", True))
            flat["parse_max_ir_nodes_per_file"] = int(p.get("max_ir_nodes_per_file", 250_000))
        if "scan" in defaults:
            sc = defaults["scan"]
            flat["scan_profile"] = str(sc.get("profile", "auto"))
            flat["scan_workers"] = int(sc.get("workers", 0))
            flat["scan_max_inflight"] = int(sc.get("max_inflight", 0))
        if "graph" in defaults:
            g = defaults["graph"]
            flat["graph_schema_version"] = str(g.get("schema_version", "3.1"))
            flat["graph_batch_size"] = int(g.get("batch_size", 500))
            flat["neo4j_uri"] = g.get("neo4j_uri") or ""
            flat["neo4j_user"] = g.get("neo4j_user", "neo4j")
            flat["neo4j_password"] = g.get("neo4j_password") or ""
        if "persistence" in defaults:
            flat["database_url"] = str(defaults["persistence"].get("database_url") or "")
        if "analysis" in defaults:
            a = defaults["analysis"]
            rp = a.get("rule_pack_path") or ""
            flat["rule_pack_path"] = Path(rp) if rp else None
            flat["rule_timeout_seconds"] = float(a.get("rule_timeout_seconds", 60))
            flat["analysis_max_same_file_flow_edges_per_file"] = int(a.get("max_same_file_flow_edges_per_file", 500))
        if "taint" in defaults:
            t = defaults["taint"]
            flat["taint_max_function_nodes"] = int(t.get("max_function_nodes", 5000))
            flat["taint_max_edges_per_function"] = int(t.get("max_edges_per_function", 50_000))
            flat["taint_max_interprocedural_flow_edges"] = int(t.get("max_interprocedural_flow_edges", 5_000))
            flat["taint_worklist_steps"] = int(t.get("worklist_steps", 200_000))
            flat["regex_taint_fallback_enabled"] = bool(t.get("regex_taint_fallback_enabled", False))
        if "agents" in defaults:
            a = defaults["agents"]
            flat["agents_enabled"] = bool(a.get("enabled", False))
            flat["agents_max_tool_calls"] = int(a.get("max_tool_calls", 32))
            flat["llm_model"] = str(a.get("llm_model", ""))
        if "semantic" in defaults:
            s = defaults["semantic"]
            flat["semantic_ir_v2_enabled"] = bool(s.get("ir_v2_enabled", False))
            flat["resolver_interprocedural_enabled"] = bool(s.get("resolver_interprocedural_enabled", False))
            flat["cfg_ssa_enabled"] = bool(s.get("cfg_ssa_enabled", False))
            flat["taint_path_sensitive_enabled"] = bool(s.get("taint_path_sensitive_enabled", False))
            flat["wp_semantics_v2_enabled"] = bool(s.get("wp_semantics_v2_enabled", False))
            flat["security_popchain_enabled"] = bool(s.get("security_popchain_enabled", False))
            flat["semantic_diff_enabled"] = bool(s.get("semantic_diff_enabled", False))
            flat["incremental_recompute_enabled"] = bool(s.get("incremental_recompute_enabled", False))
            flat["neo4j_layered_write_enabled"] = bool(s.get("neo4j_layered_write_enabled", False))
            flat["semantic_max_functions"] = int(s.get("max_functions", 20_000))
            flat["semantic_max_cfg_blocks"] = int(s.get("max_cfg_blocks", 250_000))
        if "confidence" in defaults:
            cw = defaults["confidence"].get("weights_path") or ""
            flat["confidence_weights_path"] = Path(cw) if cw else None
        if "reporting" in defaults:
            r = defaults["reporting"]
            flat["reporting_summary_grouped"] = bool(r.get("summary_grouped", True))
            flat["reporting_summary_min_confidence"] = float(r.get("summary_min_confidence", 0.0))
            flat["reporting_summary_exclude_rules"] = list(r.get("summary_exclude_rules") or [])
            flat["reporting_summary_max_groups"] = int(r.get("summary_max_groups", 500))
            flat["reporting_summary_include_blocked"] = bool(r.get("summary_include_blocked", False))
            flat["reporting_summary_triage_min_bucket"] = str(r.get("summary_triage_min_bucket", "MEDIUM"))
        if "observability" in defaults:
            o = defaults["observability"]
            flat["otel_enabled"] = bool(o.get("otel_enabled", False))
            flat["log_level"] = str(o.get("log_level", "INFO"))
        return cls(**flat)


def hunter_build_version() -> str:
    return __version__
