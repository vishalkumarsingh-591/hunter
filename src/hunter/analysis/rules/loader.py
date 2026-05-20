from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

_PACKS_DIR = Path(__file__).resolve().parent / "packs"
_MAX_INCLUDE_DEPTH = 4


class RuleSpec(BaseModel):
    id: str
    description: str = ""
    severity_band: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    python_evaluator_id: str
    min_graph_schema_version: str = "1"
    enabled: bool = True
    evaluator_params: dict[str, Any] = Field(default_factory=dict)
    owasp_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    requires_adapter: str = ""


def schema_meets_minimum(live: str, required: str) -> bool:
    """Lexicographic compare for opaque schema version strings (e.g. '1', '2')."""
    return live >= required


class RulePack(BaseModel):
    pack_id: str
    version: str
    rules: list[RuleSpec] = Field(default_factory=list)
    includes: list[str] = Field(default_factory=list)


def _resolve_pack_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    if path.exists():
        return path
    candidate = _PACKS_DIR / path.name
    if candidate.exists():
        return candidate
    return path


def load_rule_pack(path: Path, *, _depth: int = 0, _seen: set[str] | None = None) -> RulePack:
    if _depth > _MAX_INCLUDE_DEPTH:
        raise ValueError("rule pack include depth exceeded")
    resolved = _resolve_pack_path(path)
    seen = _seen or set()
    key = str(resolved.resolve())
    if key in seen:
        raise ValueError(f"rule pack include cycle: {resolved}")
    seen.add(key)
    with open(resolved, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    pack = RulePack.model_validate(raw)
    if not pack.includes:
        return pack
    merged_rules: list[RuleSpec] = []
    rule_ids: set[str] = set()
    base_dir = resolved.parent
    for inc in pack.includes:
        inc_path = _resolve_pack_path(base_dir / inc)
        sub = load_rule_pack(inc_path, _depth=_depth + 1, _seen=seen)
        for rule in sub.rules:
            if rule.id not in rule_ids:
                merged_rules.append(rule)
                rule_ids.add(rule.id)
    for rule in pack.rules:
        if rule.id not in rule_ids:
            merged_rules.append(rule)
            rule_ids.add(rule.id)
    return RulePack(
        pack_id=pack.pack_id,
        version=pack.version,
        rules=sorted(merged_rules, key=lambda r: r.id),
        includes=[],
    )


def rule_pack_hash(pack: RulePack) -> str:
    import hashlib
    import json

    canonical = json.dumps(pack.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def default_pack_path() -> Path:
    return _PACKS_DIR / "default.yaml"


def pack_path_for_profile(profile_id: str) -> Path:
    mapping = {
        "generic-php": _PACKS_DIR / "generic-php.yaml",
        "wordpress": _PACKS_DIR / "wordpress.yaml",
        "full": _PACKS_DIR / "full.yaml",
    }
    return mapping.get(profile_id, _PACKS_DIR / "full.yaml")
