"""Group enriched findings for human-readable summaries."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from hunter.models.findings import EnrichedFinding

_BUCKET_ORDER = ("VERY_HIGH", "HIGH", "MEDIUM", "LOW", "VERY_LOW")


@dataclass
class SummaryGroup:
    group_id: str
    rule_id: str
    file_rel_path: str
    sink_line: int
    count: int
    finding_ids: list[str] = field(default_factory=list)
    max_confidence: float = 0.0
    min_confidence: float = 1.0
    bucket_counts: dict[str, int] = field(default_factory=dict)
    sample_source_lines: list[int] = field(default_factory=list)
    severity_static: str = ""
    skeptic_downgrade_count: int = 0
    skeptic_blocked_count: int = 0


def summary_group_key(e: EnrichedFinding) -> str:
    c = e.candidate
    if len(c.anchors) >= 2:
        sink = c.anchors[-1]
        return f"{c.rule_id}|{sink.file_rel_path}|{sink.start_line}"
    if c.anchors:
        a = c.anchors[0]
        return f"{c.rule_id}|{a.file_rel_path}|{a.start_line}"
    return f"{c.rule_id}|unknown|0"


def build_summary_groups(enriched: list[EnrichedFinding]) -> list[SummaryGroup]:
    buckets: dict[str, list[EnrichedFinding]] = {}
    for e in enriched:
        buckets.setdefault(summary_group_key(e), []).append(e)

    groups: list[SummaryGroup] = []
    for gid, items in sorted(buckets.items()):
        rule_id = items[0].candidate.rule_id
        if len(items[0].candidate.anchors) >= 2:
            sink = items[0].candidate.anchors[-1]
            file_rel = sink.file_rel_path
            sink_line = sink.start_line
        elif items[0].candidate.anchors:
            file_rel = items[0].candidate.anchors[0].file_rel_path
            sink_line = items[0].candidate.anchors[0].start_line
        else:
            file_rel = "unknown"
            sink_line = 0

        scores = [it.confidence.score for it in items]
        bc: Counter[str] = Counter()
        src_lines: list[int] = []
        down = 0
        blocked = 0
        for it in items:
            bc[it.confidence.bucket] += 1
            if it.skeptic and it.skeptic.verdict == "DOWNGRADE":
                down += 1
            if it.skeptic and it.skeptic.promotion_blocked:
                blocked += 1
            if len(it.candidate.anchors) >= 2:
                src_lines.append(it.candidate.anchors[0].start_line)
            elif it.candidate.anchors:
                src_lines.append(it.candidate.anchors[0].start_line)

        groups.append(
            SummaryGroup(
                group_id=gid,
                rule_id=rule_id,
                file_rel_path=file_rel,
                sink_line=sink_line,
                count=len(items),
                finding_ids=sorted(it.candidate.finding_id for it in items),
                max_confidence=max(scores),
                min_confidence=min(scores),
                bucket_counts=dict(bc),
                sample_source_lines=sorted(set(src_lines))[:5],
                severity_static=items[0].candidate.severity_band_static,
                skeptic_downgrade_count=down,
                skeptic_blocked_count=blocked,
            )
        )
    groups.sort(key=lambda g: (-g.max_confidence, -g.count, g.rule_id, g.file_rel_path))
    return groups


def _bucket_rank(bucket: str) -> int:
    try:
        return _BUCKET_ORDER.index(bucket)
    except ValueError:
        return len(_BUCKET_ORDER)


def group_passes_triage(
    g: SummaryGroup,
    *,
    min_bucket: str,
    min_confidence: float,
    include_blocked: bool,
) -> bool:
    if g.max_confidence < min_confidence:
        return False
    if not include_blocked and g.skeptic_blocked_count == g.count:
        return False
    min_rank = _bucket_rank(min_bucket)
    for bucket, cnt in g.bucket_counts.items():
        if cnt > 0 and _bucket_rank(bucket) <= min_rank:
            return True
    return g.max_confidence >= min_confidence and min_rank >= _bucket_rank("LOW")
