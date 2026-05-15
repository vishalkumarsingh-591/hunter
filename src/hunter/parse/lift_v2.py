"""Structure-complete IR lift: declarations, callsites, and structural IREdges."""

from __future__ import annotations

import hashlib

from tree_sitter import Node, Tree

from hunter.models.ir import CommentNode, IREdge, IRNode, ParseDiagnostic
from hunter.parse.lift import _emit_node, _stable_ir_id
from hunter.parse.line_index import span_to_line_col

# Tier 1: always collected (declarations / containers)
_PHP_DECL = frozenset(
    {
        "namespace_definition",
        "class_declaration",
        "interface_declaration",
        "trait_declaration",
        "function_definition",
        "method_declaration",
    }
)
_PHP_CALL = frozenset({"call_expression", "scoped_call_expression"})
_PHP_OTHER = frozenset(
    {
        "assignment_expression",
        "expression_statement",
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
        "echo_statement",
        "print_intrinsic",
        "subscript_expression",
        "variable_name",
    }
)

_JS_DECL = frozenset({"function_declaration", "function", "arrow_function", "class_declaration", "method_definition"})
_JS_CALL = frozenset({"call_expression"})
_JS_OTHER = frozenset({"expression_statement", "assignment_expression", "member_expression"})

_HTML_DECL = frozenset({"element", "script_element", "style_element"})
_HTML_OTHER = frozenset({"attribute_name", "attribute_value"})


def _kinds_for_language(language: str) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    if language == "javascript":
        return _JS_DECL, _JS_CALL, _JS_OTHER
    if language == "html":
        return _HTML_DECL, frozenset(), _HTML_OTHER
    return _PHP_DECL, _PHP_CALL, _PHP_OTHER


def _edge_id(file_rel: str, kind: str, src: str, dst: str) -> str:
    h = hashlib.sha256(f"{file_rel}|{kind}|{src}|{dst}".encode()).hexdigest()[:12]
    return f"ire:{file_rel}:{kind}:{h}"


def _collect_tier(
    node: Node,
    file_rel: str,
    source: bytes,
    kinds: frozenset[str],
    nodes: list[IRNode],
    budget: int,
) -> int:
    if budget <= 0:
        return budget
    if node.is_named and node.type in kinds:
        _emit_node(file_rel, source, node, nodes)
        budget -= 1
    for c in node.children:
        budget = _collect_tier(c, file_rel, source, kinds, nodes, budget)
        if budget <= 0:
            return 0
    return budget


def _find_enclosing_ir(start: int, end: int, node_by_span: dict[tuple[int, int], str]) -> str | None:
    """Return IR id of innermost declaration containing byte span."""
    best: tuple[int, int, str] | None = None
    for (ds, de), iid in node_by_span.items():
        if ds <= start and end <= de:
            if best is None or (de - ds) < (best[1] - best[0]):
                best = (ds, de, iid)
    return best[2] if best else None


def _build_structural_edges(
    file_rel: str,
    source: bytes,
    nodes: list[IRNode],
    edges: list[IREdge],
    decl_kinds: frozenset[str],
) -> None:
    fn_kinds = decl_kinds | {"function_definition", "method_declaration", "function", "arrow_function"}
    decl_nodes = [n for n in nodes if n.kind in fn_kinds]
    node_by_span = {(n.start_byte, n.end_byte): n.id for n in decl_nodes}
    class_kinds = {"class_declaration", "interface_declaration", "trait_declaration", "class_declaration"}
    for n in nodes:
        if n.kind in class_kinds:
            for m in nodes:
                if m.kind == "method_declaration" and m.start_byte >= n.start_byte and m.end_byte <= n.end_byte:
                    edges.append(
                        IREdge(
                            id=_edge_id(file_rel, "CONTAINS", n.id, m.id),
                            src_id=n.id,
                            dst_id=m.id,
                            kind="CONTAINS",
                        )
                    )
        if n.kind in ("function_definition", "method_declaration", "function", "arrow_function"):
            edges.append(
                IREdge(
                    id=_edge_id(file_rel, "DEFINED_IN", n.id, file_rel),
                    src_id=n.id,
                    dst_id=f"file:{file_rel}",
                    kind="DEFINED_IN",
                    properties={"file_rel_path": file_rel},
                )
            )
    call_kinds = _PHP_CALL | _JS_CALL
    for n in nodes:
        if n.kind not in call_kinds:
            continue
        parent_id = _find_enclosing_ir(n.start_byte, n.end_byte, node_by_span)
        if parent_id:
            edges.append(
                IREdge(
                    id=_edge_id(file_rel, "CALLS", parent_id, n.id),
                    src_id=parent_id,
                    dst_id=n.id,
                    kind="CALLS",
                )
            )


def lift_tree_v2(
    tree: Tree,
    file_rel: str,
    source: bytes,
    language: str,
    *,
    max_nodes: int = 250_000,
) -> tuple[list[IRNode], list[IREdge], list[CommentNode], list[ParseDiagnostic], bool]:
    """Returns (nodes, edges, comments, diagnostics, truncated)."""
    diagnostics: list[ParseDiagnostic] = []
    if tree.root_node.has_error:
        diagnostics.append(ParseDiagnostic(code="SYNTAX_ERROR", message="parse tree has_error", line=None))
    decl_k, call_k, other_k = _kinds_for_language(language)
    nodes: list[IRNode] = []
    budget = max_nodes
    budget = _collect_tier(tree.root_node, file_rel, source, decl_k, nodes, budget)
    if budget > 0:
        budget = _collect_tier(tree.root_node, file_rel, source, call_k, nodes, budget)
    if budget > 0:
        budget = _collect_tier(tree.root_node, file_rel, source, other_k, nodes, budget)
    truncated = budget <= 0
    if truncated:
        diagnostics.append(
            ParseDiagnostic(
                code="IR_BUDGET_EXCEEDED",
                message=f"lift v2 stopped after {max_nodes} nodes",
                line=None,
            )
        )
    nodes.sort(key=lambda n: (n.start_byte, n.end_byte, n.kind))
    edges: list[IREdge] = []
    _build_structural_edges(file_rel, source, nodes, edges, decl_k)
    edges.sort(key=lambda e: (e.kind, e.src_id, e.dst_id))
    return nodes, edges, [], diagnostics, truncated
