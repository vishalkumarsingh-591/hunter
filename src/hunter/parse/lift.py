from __future__ import annotations

from tree_sitter import Node, Tree

from hunter.models.ir import CommentNode, IREdge, IRNode, ParseDiagnostic
from hunter.parse.line_index import span_to_line_col

_PHP_KINDS = frozenset(
    {
        "namespace_definition",
        "class_declaration",
        "function_definition",
        "method_declaration",
        "call_expression",
        "scoped_call_expression",
        "echo_statement",
        "print_intrinsic",
        "assignment_expression",
        "expression_statement",
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
        "subscript_expression",
        "variable_name",
        "name",
        "string",
        "string_content",
    }
)

_JS_KINDS = frozenset(
    {
        "function_declaration",
        "function",
        "arrow_function",
        "call_expression",
        "member_expression",
        "expression_statement",
        "assignment_expression",
        "string",
    }
)

_HTML_KINDS = frozenset({"element", "script_element", "style_element", "attribute_name"})


def _stable_ir_id(file_rel: str, start: int, end: int, kind: str) -> str:
    safe = file_rel.replace("\\", "/")
    return f"ir:{safe}:{start}:{end}:{kind}"


def _emit_node(file_rel: str, source: bytes, node: Node, nodes: list[IRNode]) -> None:
    start, end = node.start_byte, node.end_byte
    if end <= start:
        return
    sl, sc, el, ec = span_to_line_col(source, start, end)
    label = source[start:end].decode("utf-8", errors="replace")[:240]
    nodes.append(
        IRNode(
            id=_stable_ir_id(file_rel, start, end, node.type),
            kind=node.type,
            label=label,
            file_rel_path=file_rel,
            start_byte=start,
            end_byte=end,
            start_line=sl,
            start_col=sc,
            end_line=el,
            end_col=ec,
            properties={"named": node.is_named},
        )
    )


def _walk_collect(
    node: Node,
    file_rel: str,
    source: bytes,
    kinds: frozenset[str],
    nodes: list[IRNode],
    budget: int,
) -> int:
    """Returns remaining budget."""
    if budget <= 0:
        return budget
    if node.is_named and node.type in kinds:
        _emit_node(file_rel, source, node, nodes)
        budget -= 1
    for c in node.children:
        budget = _walk_collect(c, file_rel, source, kinds, nodes, budget)
        if budget <= 0:
            break
    return budget


def lift_tree(
    tree: Tree,
    file_rel: str,
    source: bytes,
    language: str,
    *,
    max_nodes: int = 100_000,
) -> tuple[list[IRNode], list[IREdge], list[CommentNode], list[ParseDiagnostic]]:
    diagnostics: list[ParseDiagnostic] = []
    if tree.root_node.has_error:
        diagnostics.append(ParseDiagnostic(code="SYNTAX_ERROR", message="parse tree has_error", line=None))
    kinds = _PHP_KINDS
    if language == "javascript":
        kinds = _JS_KINDS
    elif language == "html":
        kinds = _HTML_KINDS
    nodes: list[IRNode] = []
    edges: list[IREdge] = []
    comments: list[CommentNode] = []
    remaining = _walk_collect(tree.root_node, file_rel, source, kinds, nodes, max_nodes)
    if remaining <= 0:
        diagnostics.append(
            ParseDiagnostic(
                code="IR_BUDGET_EXCEEDED",
                message=f"lift stopped after {max_nodes} nodes",
                line=None,
            )
        )
    # deterministic order
    nodes.sort(key=lambda n: (n.start_byte, n.end_byte, n.kind))
    return nodes, edges, comments, diagnostics
