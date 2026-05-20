from __future__ import annotations

import hashlib
import re
from typing import Any

from hunter.analysis.rules.graph_queries import (
    flows_to_edges,
    has_sql_prepare_between,
    heuristic_patterns,
    source_sink_pair,
)
from hunter.graph.in_memory import InMemoryGraph
from hunter.models.core import RepoManifest
from hunter.models.findings import (
    CandidateFinding,
    ExposureContext,
    LocationAnchor,
    Witness,
    WitnessHop,
    WPContextFeatures,
)

_STATIC_INCLUDE_PATH = re.compile(
    r"require(_once)?\s+.*__DIR__|plugin_dir_path|dirname\s*\(\s*__FILE__",
    re.IGNORECASE,
)
_PRIMARY_SOURCES = frozenset({"$_GET", "$_POST", "$_REQUEST"})


def _witness_hash(w: Witness) -> str:
    import json

    payload = json.dumps(w.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _finding_id(rule_id: str, anchor_id: str, sink_id: str, witness_hash: str) -> str:
    return f"FINDING|{rule_id}|{anchor_id}|{sink_id}|{witness_hash}"


def _anchor_for_node(nid: str, n: dict, *, file_rel: str) -> LocationAnchor:
    line = int(n.get("line", 0))
    return LocationAnchor(
        file_rel_path=file_rel or str(n.get("file", "")),
        start_line=line,
        end_line=line,
        start_col=0,
        end_col=0,
        start_byte=0,
        end_byte=0,
        ir_node_id=str(n.get("ir_node_id", nid)),
    )


def _source_name(sn: dict) -> str:
    return str(sn.get("name", ""))


def _flow_passes_rule_gates(
    g: InMemoryGraph,
    e: dict[str, Any],
    sn: dict,
    sk: dict,
    rule_id: str,
    params: dict[str, Any],
) -> bool:
    source_line = int(sn.get("line", 0))
    sink_line = int(sk.get("line", 0))
    if source_line == sink_line and source_line > 0:
        return False
    if params.get("require_non_static_sink") and (sk.get("static_arg") or sk.get("static_path_likely")):
        return False
    if rule_id == "RULE-LFI-001" and sk.get("static_arg"):
        return False
    if rule_id == "RULE-LFI-001":
        sink_nid = e["dst"]
        # Best-effort: skip known-safe static include patterns from callsite/IR text in graph
        for nid, n in g.nodes.items():
            if nid == sink_nid or n.get("file") != sn.get("file"):
                continue
            if int(n.get("line", -1)) == sink_line and str(nid).startswith("callsite:"):
                if _STATIC_INCLUDE_PATH.search(str(n.get("label_preview", ""))):
                    return False
    if params.get("require_primary_sources") and _source_name(sn) not in _PRIMARY_SOURCES:
        return False
    if rule_id in ("RULE-RCE-001", "RULE-UPLOAD-001", "RULE-LFI-001", "RULE-RFI-001"):
        if _source_name(sn) not in _PRIMARY_SOURCES and _source_name(sn) not in ("$_COOKIE", "$_SERVER"):
            pass
        elif _source_name(sn) in ("$_COOKIE", "$_SERVER") and rule_id == "RULE-RCE-001":
            return False
    return True


def _witness_for_flow(
    g: InMemoryGraph,
    src: str,
    dst: str,
    edge: dict[str, Any],
    sn: dict,
    sk: dict,
    taint_labels: list[str],
    *,
    extra_sources: list[str] | None = None,
    source_count: int = 1,
) -> Witness:
    file_rel = str(sn.get("file", sk.get("file", "")))
    source_line = int(sn.get("line", 0))
    sink_line = int(sk.get("line", 0))
    sink_kind = str(sk.get("kind", ""))
    constraint_summary: dict[str, int | float | bool | str] = {}
    semantic_trace: list[str] = [f"graph:source:{src}", f"graph:sink:{dst}"]
    limits: list[str] = ["exposure_not_gated"]
    if extra_sources:
        for xs in extra_sources[:5]:
            semantic_trace.append(f"graph:alt_source:{xs}")
    if source_count > 1:
        constraint_summary["source_count"] = source_count
    if edge.get("from_lift"):
        semantic_trace.append("lift_derived_flow")
    if edge.get("via") == "interprocedural":
        semantic_trace.append("interprocedural_taint_approximation")
        limits.append("coarse_taint_approximation")
        limits.append("interprocedural_heuristic")
    cs = edge.get("constraint_strength")
    if cs is not None:
        constraint_summary["constraint_strength"] = float(cs)
    uc = edge.get("unresolved_calls")
    if uc is not None:
        constraint_summary["unresolved_calls"] = int(uc)
    if int(uc or 0) > 0:
        limits.append("dynamic_call_resolution_incomplete")
    if sink_kind == "SQL" and has_sql_prepare_between(g, file_rel, source_line, sink_line):
        constraint_summary["sql_prepare_on_path"] = True
    if edge.get("approx"):
        constraint_summary["approximate_flow"] = True
    return Witness(
        path_edges=[f"{src}|FLOWS_TO|{dst}"],
        summary_hops=[WitnessHop(from_id=src, to_id=dst, edge_kind="FLOWS_TO")],
        taint_labels=taint_labels,
        semantic_trace=semantic_trace,
        constraint_summary=constraint_summary,
        analysis_limits=limits,
    )


def _collect_flow_findings(
    g: InMemoryGraph,
    *,
    sink_kind: str,
    rule_id: str,
    severity: str,
    title_key: str,
    taint_labels: list[str],
    params: dict[str, Any] | None = None,
) -> list[CandidateFinding]:
    p = params or {}
    emit_one = bool(p.get("emit_one_per_sink", True))
    by_sink: dict[tuple[str, int], list[tuple[dict, dict, dict, str, str]]] = {}
    out: list[CandidateFinding] = []

    for e in flows_to_edges(g):
        pair = source_sink_pair(g, e["src"], e["dst"])
        if pair is None:
            continue
        sn, sk = pair
        if sk.get("kind") != sink_kind:
            continue
        if not _flow_passes_rule_gates(g, e, sn, sk, rule_id, p):
            continue
        file_rel = str(sn.get("file", ""))
        sink_line = int(sk.get("line", 0))
        key = (file_rel, sink_line)
        if emit_one:
            by_sink.setdefault(key, []).append((e, sn, sk, e["src"], e["dst"]))
        else:
            w = _witness_for_flow(g, e["src"], e["dst"], e, sn, sk, taint_labels)
            wid = _witness_hash(w)
            out.append(
                CandidateFinding(
                    finding_id=_finding_id(rule_id, e["src"], e["dst"], wid),
                    rule_id=rule_id,
                    severity_band_static=severity,  # type: ignore[arg-type]
                    title_template_key=title_key,
                    anchors=[
                        _anchor_for_node(e["src"], sn, file_rel=file_rel),
                        _anchor_for_node(e["dst"], sk, file_rel=file_rel),
                    ],
                    witness=w,
                    wp_context=WPContextFeatures(),
                )
            )

    if emit_one:
        for (_file_rel, _sink_line), rows in sorted(by_sink.items()):
            e, sn, sk, rep_src, rep_dst = rows[0]
            file_rel = str(sn.get("file", ""))
            alt = [r[3] for r in rows[1:6]]
            w = _witness_for_flow(
                g,
                rep_src,
                rep_dst,
                e,
                sn,
                sk,
                taint_labels,
                extra_sources=alt,
                source_count=len(rows),
            )
            wid = _witness_hash(w)
            out.append(
                CandidateFinding(
                    finding_id=_finding_id(rule_id, rep_dst, rep_dst, wid),
                    rule_id=rule_id,
                    severity_band_static=severity,  # type: ignore[arg-type]
                    title_template_key=title_key,
                    anchors=[
                        _anchor_for_node(rep_src, sn, file_rel=file_rel),
                        _anchor_for_node(rep_dst, sk, file_rel=file_rel),
                    ],
                    witness=w,
                    wp_context=WPContextFeatures(),
                )
            )
    return out


def eval_sqli_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    """Graph-only SQLi: Source -> Sink(SQL) without SQL prepare mitigation on path."""
    out: list[CandidateFinding] = []
    seen_sink: set[tuple[str, int]] = set()
    for e in flows_to_edges(g):
        pair = source_sink_pair(g, e["src"], e["dst"])
        if pair is None:
            continue
        sn, sk = pair
        if sk.get("kind") != "SQL":
            continue
        if not _flow_passes_rule_gates(g, e, sn, sk, "RULE-SQLI-001", {"emit_one_per_sink": True}):
            continue
        file_rel = str(sn.get("file", ""))
        source_line = int(sn.get("line", 0))
        sink_line = int(sk.get("line", 0))
        if has_sql_prepare_between(g, file_rel, source_line, sink_line):
            continue
        sk_key = (file_rel, sink_line)
        if sk_key in seen_sink:
            continue
        seen_sink.add(sk_key)
        w = _witness_for_flow(g, e["src"], e["dst"], e, sn, sk, ["HTTP_SUPERGLOBAL", "SQL"])
        wid = _witness_hash(w)
        out.append(
            CandidateFinding(
                finding_id=_finding_id("RULE-SQLI-001", e["dst"], e["dst"], wid),
                rule_id="RULE-SQLI-001",
                severity_band_static="MEDIUM",
                title_template_key="sqli.graph_flow",
                anchors=[
                    _anchor_for_node(e["src"], sn, file_rel=file_rel),
                    _anchor_for_node(e["dst"], sk, file_rel=file_rel),
                ],
                witness=w,
                wp_context=WPContextFeatures(),
            )
        )
    return out


def eval_xss_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    return _collect_flow_findings(
        g,
        sink_kind="HTML",
        rule_id="RULE-XSS-001",
        severity="LOW",
        title_key="xss.graph_flow",
        taint_labels=["HTTP_SUPERGLOBAL", "HTML"],
        params={"emit_one_per_sink": True},
    )


def eval_ajax_nopriv_no_cap(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    out: list[CandidateFinding] = []
    files_with_cap = {n.get("file") for n in g.nodes.values() if n.get("label") == "CapabilityCheck" and n.get("file")}
    handler_guarded: set[str] = set()
    for e in g.edges:
        if e["rel"] != "HANDLED_BY":
            continue
        handler = g.nodes.get(e["dst"], {})
        if handler.get("has_capability_guard") or handler.get("has_nonce_guard"):
            handler_guarded.add(str(e["src"]))
    for nid, n in g.nodes.items():
        if n.get("label") != "AjaxAction" or not n.get("nopriv"):
            continue
        if nid in handler_guarded:
            continue
        file_rel = str(n.get("file", ""))
        if file_rel in files_with_cap:
            continue
        line = int(n.get("line", 0))
        anchor = LocationAnchor(
            file_rel_path=file_rel,
            start_line=line,
            end_line=line,
            start_col=0,
            end_col=0,
            start_byte=0,
            end_byte=0,
            ir_node_id=nid,
        )
        w = Witness(
            path_edges=[nid],
            summary_hops=[],
            taint_labels=["AJAX_NOPRIV"],
            semantic_trace=[f"graph:ajax:{nid}"],
        )
        wid = _witness_hash(w)
        out.append(
            CandidateFinding(
                finding_id=_finding_id("RULE-WP-AJAX-001", nid, nid, wid),
                rule_id="RULE-WP-AJAX-001",
                severity_band_static="HIGH",
                title_template_key="wp.ajax_nopriv_no_cap",
                anchors=[anchor],
                witness=w,
                wp_context=WPContextFeatures(ajax_nopriv=True, exposure="AJAX_NOPRIV"),
                exposure_context=ExposureContext(surface="HTTP_PUBLIC", framework="wordpress"),
            )
        )
    return out


def eval_wp_nonce_get_only(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    """Graph-only: HeuristicPattern NONCE_GET_ONLY nodes."""
    out: list[CandidateFinding] = []
    for nid, n in heuristic_patterns(g, "NONCE_GET_ONLY"):
        file_rel = str(n.get("file", ""))
        line = int(n.get("line", 0))
        anchor = LocationAnchor(
            file_rel_path=file_rel,
            start_line=line,
            end_line=line,
            start_col=0,
            end_col=0,
            start_byte=0,
            end_byte=0,
            ir_node_id=nid,
        )
        w = Witness(
            path_edges=[nid],
            summary_hops=[],
            taint_labels=["WP_NONCE", "METHOD_GUARD_GET_ONLY"],
            semantic_trace=[f"graph:pattern:{nid}"],
        )
        wid = _witness_hash(w)
        out.append(
            CandidateFinding(
                finding_id=_finding_id("RULE-WP-NONCE-001", nid, nid, wid),
                rule_id="RULE-WP-NONCE-001",
                severity_band_static="MEDIUM",
                title_template_key="wp.nonce_get_only",
                anchors=[anchor],
                witness=w,
                wp_context=WPContextFeatures(exposure="UNKNOWN", nonce_guard_approx=True),
            )
        )
    return out


def eval_object_injection_signal(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    out: list[CandidateFinding] = []
    for nid, n in g.nodes.items():
        if n.get("label") != "SecuritySignal":
            continue
        if n.get("signal") != "OBJECT_INJECTION_ENTRYPOINT":
            continue
        file_rel = str(n.get("file", ""))
        line = int(n.get("line", 0))
        anchor = LocationAnchor(
            file_rel_path=file_rel,
            start_line=line,
            end_line=line,
            start_col=0,
            end_col=0,
            start_byte=0,
            end_byte=0,
            ir_node_id=nid,
        )
        w = Witness(
            path_edges=[nid],
            summary_hops=[],
            taint_labels=["DESERIALIZE"],
            semantic_trace=[f"graph:security_signal:{nid}"],
            constraint_summary={"constraint_strength": 35},
        )
        wid = _witness_hash(w)
        out.append(
            CandidateFinding(
                finding_id=_finding_id("RULE-OBJINJ-001", nid, nid, wid),
                rule_id="RULE-OBJINJ-001",
                severity_band_static="MEDIUM",
                title_template_key="php.object_injection.signal",
                anchors=[anchor],
                witness=w,
                wp_context=WPContextFeatures(exposure="UNKNOWN"),
            )
        )
    return out


def eval_flow_to_sink_kind(
    g: InMemoryGraph,
    manifest: RepoManifest,
    *,
    sink_kind: str,
    rule_id: str,
    severity: str,
    title_key: str,
    taint_labels: list[str],
    params: dict[str, Any] | None = None,
) -> list[CandidateFinding]:
    return _collect_flow_findings(
        g,
        sink_kind=sink_kind,
        rule_id=rule_id,
        severity=severity,
        title_key=title_key,
        taint_labels=taint_labels,
        params=params,
    )


def eval_redirect_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    return eval_flow_to_sink_kind(
        g,
        manifest,
        sink_kind="REDIRECT",
        rule_id="RULE-REDIRECT-001",
        severity="MEDIUM",
        title_key="redirect.graph_flow",
        taint_labels=["HTTP_SUPERGLOBAL", "REDIRECT"],
        params={"emit_one_per_sink": True},
    )


def eval_lfi_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    return eval_flow_to_sink_kind(
        g,
        manifest,
        sink_kind="FILE_INCLUDE",
        rule_id="RULE-LFI-001",
        severity="MEDIUM",
        title_key="lfi.graph_flow",
        taint_labels=["FILE_INCLUDE"],
        params={"require_non_static_sink": True, "emit_one_per_sink": True},
    )


def eval_rfi_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    return eval_flow_to_sink_kind(
        g,
        manifest,
        sink_kind="REMOTE_READ",
        rule_id="RULE-RFI-001",
        severity="HIGH",
        title_key="rfi.graph_flow",
        taint_labels=["REMOTE_READ"],
        params={"require_non_static_sink": True, "emit_one_per_sink": True},
    )


def eval_rce_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    return eval_flow_to_sink_kind(
        g,
        manifest,
        sink_kind="CODE_EXEC",
        rule_id="RULE-RCE-001",
        severity="CRITICAL",
        title_key="rce.graph_flow",
        taint_labels=["CODE_EXEC"],
        params={"require_primary_sources": True, "emit_one_per_sink": True},
    )


def eval_upload_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    return eval_flow_to_sink_kind(
        g,
        manifest,
        sink_kind="UPLOAD",
        rule_id="RULE-UPLOAD-001",
        severity="HIGH",
        title_key="upload.graph_flow",
        taint_labels=["UPLOAD"],
        params={"require_non_static_sink": True, "emit_one_per_sink": True},
    )


def eval_ssrf_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    return eval_flow_to_sink_kind(
        g,
        manifest,
        sink_kind="HTTP_CLIENT",
        rule_id="RULE-SSRF-001",
        severity="LOW",
        title_key="ssrf.graph_flow",
        taint_labels=["SSRF"],
        params={"emit_one_per_sink": True},
    )


def eval_csv_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    return eval_flow_to_sink_kind(
        g,
        manifest,
        sink_kind="CSV_OUTPUT",
        rule_id="RULE-CSV-001",
        severity="LOW",
        title_key="csv.graph_flow",
        taint_labels=["CSV"],
        params={"emit_one_per_sink": True},
    )


def eval_wp_rest_weak(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    out: list[CandidateFinding] = []
    for e in g.edges:
        if e["rel"] != "MISSING_GUARD":
            continue
        route = g.nodes.get(e["src"], {})
        if route.get("label") != "Route":
            continue
        nid = e["src"]
        file_rel = str(route.get("file", ""))
        line = 1
        anchor = LocationAnchor(
            file_rel_path=file_rel,
            start_line=line,
            end_line=line,
            start_col=0,
            end_col=0,
            start_byte=0,
            end_byte=0,
            ir_node_id=nid,
        )
        w = Witness(path_edges=[nid], semantic_trace=[f"graph:route:{nid}"], taint_labels=["REST", "ACCESS_CONTROL"])
        wid = _witness_hash(w)
        out.append(
            CandidateFinding(
                finding_id=_finding_id("RULE-WP-REST-001", nid, nid, wid),
                rule_id="RULE-WP-REST-001",
                severity_band_static="HIGH",
                title_template_key="wp.rest_weak_permission",
                anchors=[anchor],
                witness=w,
                wp_context=WPContextFeatures(exposure="PUBLIC_AUTHENTICATED"),
            )
        )
    return out


def eval_wp_idor_graph(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    """Heuristic: HTTP source flow to sink without cap check in same file."""
    allowed = frozenset({"SQL", "HTML", "OBJECT_INJECTION"})
    params = {"emit_one_per_sink": True}
    out: list[CandidateFinding] = []
    files_with_cap = {n.get("file") for n in g.nodes.values() if n.get("label") == "CapabilityCheck"}
    by_sink: dict[tuple[str, int, str], list[tuple]] = {}
    for e in flows_to_edges(g):
        pair = source_sink_pair(g, e["src"], e["dst"])
        if pair is None:
            continue
        sn, sk = pair
        file_rel = str(sn.get("file", ""))
        if file_rel in files_with_cap:
            continue
        skind = str(sk.get("kind", ""))
        if skind not in allowed:
            continue
        if not _flow_passes_rule_gates(g, e, sn, sk, "RULE-WP-IDOR-001", params):
            continue
        sink_line = int(sk.get("line", 0))
        by_sink.setdefault((file_rel, sink_line, skind), []).append((e, sn, sk))

    for (_file_rel, _sink_line, _skind), rows in sorted(by_sink.items()):
        e, sn, sk = rows[0]
        file_rel = str(sn.get("file", ""))
        rep_src, rep_dst = e["src"], e["dst"]
        w = _witness_for_flow(
            g,
            rep_src,
            rep_dst,
            e,
            sn,
            sk,
            ["IDOR", "HTTP_SUPERGLOBAL"],
            extra_sources=[r[0]["src"] for r in rows[1:6]],
            source_count=len(rows),
        )
        w.analysis_limits.append("idor_heuristic_no_object_ownership_model")
        wid = _witness_hash(w)
        out.append(
            CandidateFinding(
                finding_id=_finding_id("RULE-WP-IDOR-001", rep_dst, rep_dst, wid),
                rule_id="RULE-WP-IDOR-001",
                severity_band_static="MEDIUM",
                title_template_key="wp.idor.graph_heuristic",
                anchors=[
                    _anchor_for_node(rep_src, sn, file_rel=file_rel),
                    _anchor_for_node(rep_dst, sk, file_rel=file_rel),
                ],
                witness=w,
                wp_context=WPContextFeatures(exposure="UNKNOWN"),
            )
        )
    return out


EVALUATORS = {
    "sqli_graph": eval_sqli_graph,
    "xss_graph": eval_xss_graph,
    "wp_nonce_get_only": eval_wp_nonce_get_only,
    "ajax_nopriv_no_cap": eval_ajax_nopriv_no_cap,
    "object_injection_signal": eval_object_injection_signal,
    "redirect_graph": eval_redirect_graph,
    "lfi_graph": eval_lfi_graph,
    "rfi_graph": eval_rfi_graph,
    "rce_graph": eval_rce_graph,
    "upload_graph": eval_upload_graph,
    "ssrf_graph": eval_ssrf_graph,
    "csv_graph": eval_csv_graph,
    "wp_rest_weak": eval_wp_rest_weak,
    "wp_idor_graph": eval_wp_idor_graph,
}
