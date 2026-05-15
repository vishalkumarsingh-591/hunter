from __future__ import annotations

import re
from collections.abc import Iterable

FINDING_REPORT_SCHEMA_VERSION = "FindingReportV1"

# Contract keys that external consumers already rely on.
REPORT_TOP_LEVEL_KEYS = (
    "schema_version",
    "scan_id",
    "snapshot_id",
    "replay_token",
    "graph_integrity_ok",
    "findings",
)

REQUIRED_FINDING_KEYS = (
    "candidate",
    "verification",
    "confidence",
)

FINDING_ID_PATTERN = re.compile(r"^FINDING\|[^|]+\|[^|]+\|[^|]+\|[0-9a-f]{16}$")


def has_required_keys(payload: dict, required_keys: Iterable[str]) -> bool:
    return all(k in payload for k in required_keys)
