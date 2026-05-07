from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


class RuleSpec(BaseModel):
    id: str
    description: str = ""
    severity_band: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    python_evaluator_id: str


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
