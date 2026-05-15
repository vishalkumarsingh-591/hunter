from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hunter.models.core import RepoManifest

if TYPE_CHECKING:
    from hunter.graph.in_memory import InMemoryGraph

_FUNC_DEF = re.compile(r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")
_CALL = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")
_MAGIC_METHOD = re.compile(r"function\s+(__[a-zA-Z0-9_]+)\s*\(")

_LANG_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "echo",
    "isset",
    "empty",
    "array",
}


@dataclass
class ResolutionNode:
    function_name: str
    file_rel_path: str
    line: int


@dataclass
class ResolutionEdge:
    caller: str
    callee: str
    file_rel_path: str
    line: int
    resolution_kind: str


@dataclass
class ResolutionResult:
    nodes: list[ResolutionNode] = field(default_factory=list)
    edges: list[ResolutionEdge] = field(default_factory=list)
    unresolved_calls: int = 0
    magic_methods: list[str] = field(default_factory=list)


def _line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def build_interprocedural_resolution(
    manifest: RepoManifest,
    *,
    max_functions: int = 20_000,
    graph: InMemoryGraph | None = None,
) -> ResolutionResult:
    """Build resolution from structure-complete graph (manifest-only path removed)."""
    del manifest, max_functions
    if graph is None:
        return ResolutionResult()
    from hunter.analysis.semantic.resolver_graph import build_resolution_from_graph

    return build_resolution_from_graph(graph)
