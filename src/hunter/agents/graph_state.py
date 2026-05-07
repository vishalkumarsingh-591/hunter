from __future__ import annotations

from typing import NotRequired, TypedDict


class AgentState(TypedDict):
    scan_id: str
    graph_integrity_ok: bool
    agents_enabled: bool
    candidates: list[dict]
    enriched: NotRequired[list[dict]]
    reasoning_trace: NotRequired[list[dict]]
