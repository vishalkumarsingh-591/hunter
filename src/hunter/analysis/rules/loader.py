from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field


class RuleSpec(BaseModel):
    id: str
    description: str = ""
    severity_band: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    python_evaluator_id: str
    min_graph_schema_version: str = "1"
    enabled: bool = True
    evaluator_params: dict[str, Any] = Field(default_factory=dict)


def schema_meets_minimum(live: str, required: str) -> bool:
    """Lexicographic compare for opaque schema version strings (e.g. '1', '2')."""
    return live >= required


class RulePack(BaseModel):
    pack_id: str
    version: str
    rules: list[RuleSpec] = Field(default_factory=list)


def load_rule_pack(path: Path) -> RulePack:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return RulePack.model_validate(raw)


def rule_pack_hash(pack: RulePack) -> str:
    import hashlib
    import json

    canonical = json.dumps(pack.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]
