from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path

from hunter.contracts import FINDING_REPORT_SCHEMA_VERSION
from hunter.models.core import DeterminismMeta, IngestResult, RepoManifest
from hunter.models.findings import EnrichedFinding
from hunter.models.ir import ParseRunResult
from hunter.reporting.grouping import (
    SummaryGroup,
    build_summary_groups,
    group_passes_triage,
)
from hunter.settings import HunterSettings

_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[^\s]+"),
)


def _redact(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


def _render_group_section(g: SummaryGroup) -> list[str]:
    lines = [
        f"## {g.rule_id} — `{g.file_rel_path}` L{g.sink_line}",
        f"- instances: **{g.count}** (see `summary_groups.json` for finding_ids)",
        f"- severity (static): **{g.severity_static}**",
        f"- confidence: max **{g.max_confidence:.3f}**, min **{g.min_confidence:.3f}**",
        f"- buckets: {', '.join(f'{k}={v}' for k, v in sorted(g.bucket_counts.items()))}",
        f"- skeptic: downgrade={g.skeptic_downgrade_count}, blocked={g.skeptic_blocked_count}",
    ]
    if g.sample_source_lines:
        lines.append(f"- sample source lines: {', '.join(str(x) for x in g.sample_source_lines)}")
    lines.append("")
    return lines


def write_scan_outputs(
    output_dir: Path,
    *,
    scan_id: str,
    manifest: RepoManifest,
    ingest: IngestResult,
    parse: ParseRunResult,
    snapshot_id: str,
    determinism: DeterminismMeta,
    enriched: list[EnrichedFinding],
    reasoning_trace: list[dict],
    graph_integrity_ok: bool,
    settings: HunterSettings | None = None,
) -> None:
    cfg = settings or HunterSettings.load()
    output_dir.mkdir(parents=True, exist_ok=True)
    for sub in (
        "repository_snapshot",
        "semantic_graph",
        "findings",
        "evidence",
        "reasoning",
        "reports",
        "logs",
        "cache",
    ):
        (output_dir / sub).mkdir(parents=True, exist_ok=True)
    findings_path = output_dir / "findings" / "enriched.jsonl"
    with open(findings_path, "w", encoding="utf-8") as f:
        for e in enriched:
            f.write(e.model_dump_json() + "\n")
    candidates_path = output_dir / "findings" / "candidates.jsonl"
    with open(candidates_path, "w", encoding="utf-8") as f:
        for e in enriched:
            f.write(e.candidate.model_dump_json() + "\n")

    report = {
        "schema_version": FINDING_REPORT_SCHEMA_VERSION,
        "scan_id": scan_id,
        "snapshot_id": snapshot_id,
        "replay_token": determinism.replay_token,
        "graph_integrity_ok": graph_integrity_ok,
        "findings": [e.model_dump() for e in enriched],
    }
    (output_dir / "reports" / "findings.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    compact = {
        "schema_version": FINDING_REPORT_SCHEMA_VERSION,
        "scan_id": scan_id,
        "snapshot_id": snapshot_id,
        "graph_integrity_ok": graph_integrity_ok,
        "candidates": [e.candidate.model_dump() for e in enriched],
        "confidence": [e.confidence.model_dump() for e in enriched],
        "verification_status": [e.verification.status for e in enriched],
    }
    (output_dir / "reports" / "findings_compact.json").write_text(
        json.dumps(compact, indent=2, sort_keys=True), encoding="utf-8"
    )

    groups = build_summary_groups(enriched)
    exclude = set(cfg.reporting_summary_exclude_rules)
    filtered = [g for g in groups if g.rule_id not in exclude and g.max_confidence >= cfg.reporting_summary_min_confidence]
    groups_payload = {
        "scan_id": scan_id,
        "total_candidates": len(enriched),
        "total_groups": len(groups),
        "groups": [asdict(g) for g in groups],
    }
    (output_dir / "reports" / "summary_groups.json").write_text(
        json.dumps(groups_payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    md_lines = [
        "# Hunter scan report",
        "",
        f"- scan_id: `{scan_id}`",
        f"- snapshot_id: `{snapshot_id}`",
        f"- graph_integrity_ok: `{graph_integrity_ok}`",
        f"- candidates: **{len(enriched)}**",
        f"- summary groups: **{len(filtered)}** (of {len(groups)} total)",
        "",
    ]
    if cfg.reporting_summary_grouped:
        shown = filtered[: cfg.reporting_summary_max_groups]
        for g in shown:
            md_lines.extend(_render_group_section(g))
        if len(filtered) > len(shown):
            md_lines.append(f"\n_… and {len(filtered) - len(shown)} more groups (see summary_groups.json)_\n")
    else:
        for e in enriched:
            c = e.candidate
            md_lines.append(f"## {c.rule_id} — {c.finding_id}")
            md_lines.append(f"- severity (static): **{c.severity_band_static}**")
            md_lines.append(f"- confidence: **{e.confidence.score:.3f}** ({e.confidence.bucket})")
            md_lines.append(f"- verification: **{e.verification.status}**")
            if e.skeptic:
                md_lines.append(f"- skeptic: **{e.skeptic.verdict}** blocked={e.skeptic.promotion_blocked}")
            for a in c.anchors[:5]:
                md_lines.append(f"- `{a.file_rel_path}` L{a.start_line}-L{a.end_line}")
            md_lines.append("")
    (output_dir / "reports" / "summary.md").write_text(_redact("\n".join(md_lines)), encoding="utf-8")

    triage_groups = [
        g
        for g in filtered
        if group_passes_triage(
            g,
            min_bucket=cfg.reporting_summary_triage_min_bucket,
            min_confidence=cfg.reporting_summary_min_confidence,
            include_blocked=cfg.reporting_summary_include_blocked,
        )
    ]
    triage_lines = [
        "# Hunter triage summary",
        "",
        f"- groups: **{len(triage_groups)}** (min bucket {cfg.reporting_summary_triage_min_bucket})",
        "",
    ]
    for g in triage_groups[: cfg.reporting_summary_max_groups]:
        triage_lines.extend(_render_group_section(g))
    (output_dir / "reports" / "summary_triage.md").write_text(_redact("\n".join(triage_lines)), encoding="utf-8")

    for e in enriched:
        safe_ev = hashlib.sha256(e.candidate.finding_id.encode()).hexdigest()[:24]
        ed = output_dir / "evidence" / safe_ev
        ed.mkdir(parents=True, exist_ok=True)
        (ed / "finding_id.txt").write_text(e.candidate.finding_id, encoding="utf-8")
        (ed / "witness_path.json").write_text(e.candidate.witness.model_dump_json(), encoding="utf-8")
        (ed / "subgraph.json").write_text(
            json.dumps({"anchors": [a.model_dump() for a in e.candidate.anchors]}, indent=2), encoding="utf-8"
        )
        excerpt_lines = []
        for a in e.candidate.anchors:
            p = Path(manifest.root_path_norm) / a.file_rel_path
            if p.is_file():
                try:
                    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                    lo = max(0, a.start_line - 1)
                    hi = min(len(lines), a.end_line + 3)
                    snippet = "\n".join(f"{i+1}|{lines[i]}" for i in range(lo, hi))
                    excerpt_lines.append(_redact(snippet[:4000]))
                except OSError:
                    excerpt_lines.append("")
        (ed / "source_excerpt.txt").write_text("\n---\n".join(excerpt_lines)[:8000], encoding="utf-8")

    with open(output_dir / "reasoning" / "trace.jsonl", "w", encoding="utf-8") as f:
        for row in reasoning_trace:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    sg = output_dir / "semantic_graph"
    (sg / "snapshot_id.txt").write_text(snapshot_id, encoding="utf-8")
    (sg / "schema_version.txt").write_text(determinism.graph_schema_version, encoding="utf-8")
    with open(sg / "parse_diagnostics.jsonl", "w", encoding="utf-8") as f:
        for rel, art in parse.per_file.items():
            for d in art.diagnostics:
                f.write(json.dumps({"file": rel, **d.model_dump()}, sort_keys=True) + "\n")
