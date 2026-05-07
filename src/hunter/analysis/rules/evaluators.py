from __future__ import annotations

import hashlib
import re

from hunter.graph.in_memory import InMemoryGraph
from hunter.models.core import RepoManifest
from hunter.models.findings import (
    CandidateFinding,
    LocationAnchor,
    Witness,
    WitnessHop,
    WPContextFeatures,
)


def _witness_hash(w: Witness) -> str:
    import json

    payload = json.dumps(w.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _finding_id(rule_id: str, anchor_id: str, sink_id: str, witness_hash: str) -> str:
    return f"FINDING|{rule_id}|{anchor_id}|{sink_id}|{witness_hash}"


def eval_sqli_file_coarse(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    out: list[CandidateFinding] = []
    for e in g.edges:
        if e["rel"] != "FLOWS_TO" or e.get("via") != "same_file_ordering":
            continue
        src, dst = e["src"], e["dst"]
        sn, sk = g.nodes.get(src, {}), g.nodes.get(dst, {})
        if sn.get("label") != "Source" or sk.get("label") != "Sink" or sk.get("kind") != "SQL":
            continue
        parts = src.split(":")
        file_rel = parts[2] if len(parts) >= 3 else ""
        line = int(sn.get("line", 0))
        sink_line = int(sk.get("line", 0))
        anchor = LocationAnchor(
            file_rel_path=file_rel,
            start_line=line,
            end_line=line,
            start_col=0,
            end_col=0,
            start_byte=0,
            end_byte=0,
            ir_node_id=src,
        )
        sink_anchor = LocationAnchor(
            file_rel_path=file_rel,
            start_line=sink_line,
            end_line=sink_line,
            start_col=0,
            end_col=0,
            start_byte=0,
            end_byte=0,
            ir_node_id=dst,
        )
        w = Witness(
            path_edges=[f"{src}|FLOWS_TO|{dst}"],
            summary_hops=[WitnessHop(from_id=src, to_id=dst, edge_kind="FLOWS_TO")],
            taint_labels=["HTTP_SUPERGLOBAL", "SQL"],
        )
        wid = _witness_hash(w)
        out.append(
            CandidateFinding(
                finding_id=_finding_id("RULE-SQLI-001", src, dst, wid),
                rule_id="RULE-SQLI-001",
                severity_band_static="MEDIUM",
                title_template_key="sqli.coarse_same_file",
                anchors=[anchor, sink_anchor],
                witness=w,
                wp_context=WPContextFeatures(),
            )
        )
    return out


def eval_xss_echo_coarse(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    out: list[CandidateFinding] = []
    for e in g.edges:
        if e["rel"] != "FLOWS_TO" or e.get("via") != "same_file_ordering":
            continue
        src, dst = e["src"], e["dst"]
        sn, sk = g.nodes.get(src, {}), g.nodes.get(dst, {})
        if sn.get("label") != "Source" or sk.get("label") != "Sink" or sk.get("kind") != "HTML":
            continue
        parts = src.split(":")
        file_rel = parts[2] if len(parts) >= 3 else ""
        line = int(sn.get("line", 0))
        sink_line = int(sk.get("line", 0))
        anchor = LocationAnchor(
            file_rel_path=file_rel,
            start_line=line,
            end_line=line,
            start_col=0,
            end_col=0,
            start_byte=0,
            end_byte=0,
            ir_node_id=src,
        )
        sink_anchor = LocationAnchor(
            file_rel_path=file_rel,
            start_line=sink_line,
            end_line=sink_line,
            start_col=0,
            end_col=0,
            start_byte=0,
            end_byte=0,
            ir_node_id=dst,
        )
        w = Witness(
            path_edges=[f"{src}|FLOWS_TO|{dst}"],
            summary_hops=[WitnessHop(from_id=src, to_id=dst, edge_kind="FLOWS_TO")],
            taint_labels=["HTTP_SUPERGLOBAL", "HTML"],
        )
        wid = _witness_hash(w)
        out.append(
            CandidateFinding(
                finding_id=_finding_id("RULE-XSS-001", src, dst, wid),
                rule_id="RULE-XSS-001",
                severity_band_static="LOW",
                title_template_key="xss.echo_coarse",
                anchors=[anchor, sink_anchor],
                witness=w,
                wp_context=WPContextFeatures(),
            )
        )
    return out


def eval_ajax_nopriv_no_cap(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    out: list[CandidateFinding] = []
    files_with_cap = {
        n.get("file")
        for n in g.nodes.values()
        if n.get("label") == "CapabilityCheck" and n.get("file")
    }
    for nid, n in g.nodes.items():
        if n.get("label") != "AjaxAction" or not n.get("nopriv"):
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
        w = Witness(path_edges=[nid], summary_hops=[], taint_labels=["AJAX_NOPRIV"])
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
            )
        )
    return out


_RE_REQUEST_OPTION = re.compile(r"\$_REQUEST\s*\[\s*['\"]option['\"]\s*\]")
_RE_GET_METHOD = re.compile(
    r"['\"]GET['\"]\s*===\s*\$_SERVER\s*\[\s*['\"]REQUEST_METHOD['\"]\s*\]", re.IGNORECASE
)
_RE_POST_METHOD = re.compile(
    r"['\"]POST['\"]\s*===\s*\$_SERVER\s*\[\s*['\"]REQUEST_METHOD['\"]\s*\]", re.IGNORECASE
)
_RE_NONCE_ON_GET = re.compile(r"\$_GET\s*\[\s*['\"]_wpnonce['\"]\s*\].*?wp_verify_nonce\s*\(", re.DOTALL)
_RE_NONCE_ANY = re.compile(r"\bwp_verify_nonce\s*\(|\bcheck_admin_referer\s*\(", re.IGNORECASE)


def _line_for_offset(text: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return text.count("\n", 0, offset) + 1


def eval_wp_nonce_get_only(g: InMemoryGraph, manifest: RepoManifest) -> list[CandidateFinding]:
    """
    Flags a common WP anti-pattern:
      - request routing based on $_REQUEST['option'] (or similar)
      - nonce verification enforced only when REQUEST_METHOD == GET
      - code continues to execute the handler for other methods (e.g., POST), allowing nonce bypass.

    This is intentionally heuristic/static (MVP). It is designed to catch cases like:
      if ( ... $_REQUEST['option'] == '...' ) {
        if ( REQUEST_METHOD == 'GET' && (missing/invalid _wpnonce || !wp_verify_nonce(...)) ) die;
        do_sensitive_thing();
      }
    """
    out: list[CandidateFinding] = []
    root = manifest.root_path_norm
    for f in manifest.files:
        if f.language_guess != "php" or not f.rel_path.lower().endswith(".php"):
            continue
        try:
            text = open(f.abs_path_norm, "r", encoding=f.encoding or "utf-8", errors="replace").read()
        except OSError:
            continue

        if not _RE_REQUEST_OPTION.search(text):
            continue
        if not _RE_GET_METHOD.search(text):
            continue
        if not _RE_NONCE_ANY.search(text):
            continue

        m_get_nonce = _RE_NONCE_ON_GET.search(text)
        if not m_get_nonce:
            continue

        # Heuristic: treat as "GET-only" when file has a GET method guard but no POST guard near it.
        # If the file has explicit POST-method nonce verification patterns, we avoid flagging to reduce FPs.
        if _RE_POST_METHOD.search(text) and "check_admin_referer" in text:
            continue

        anchor_line = _line_for_offset(text, m_get_nonce.start())
        anchor_id = f"TEXTMATCH:NONCE_GET_ONLY:{f.rel_path}:{anchor_line}"
        anchor = LocationAnchor(
            file_rel_path=f.rel_path,
            start_line=anchor_line,
            end_line=anchor_line,
            start_col=0,
            end_col=0,
            start_byte=0,
            end_byte=0,
            ir_node_id=anchor_id,
        )
        w = Witness(path_edges=[anchor_id], summary_hops=[], taint_labels=["WP_NONCE", "METHOD_GUARD_GET_ONLY"])
        wid = _witness_hash(w)
        out.append(
            CandidateFinding(
                finding_id=_finding_id("RULE-WP-NONCE-001", anchor_id, anchor_id, wid),
                rule_id="RULE-WP-NONCE-001",
                severity_band_static="MEDIUM",
                title_template_key="wp.nonce_get_only",
                anchors=[anchor],
                witness=w,
                wp_context=WPContextFeatures(exposure="UNKNOWN", nonce_guard_approx=True),
            )
        )
    return out


EVALUATORS = {
    "sqli_file_coarse": eval_sqli_file_coarse,
    "xss_echo_coarse": eval_xss_echo_coarse,
    "wp_nonce_get_only": eval_wp_nonce_get_only,
    "ajax_nopriv_no_cap": eval_ajax_nopriv_no_cap,
}
