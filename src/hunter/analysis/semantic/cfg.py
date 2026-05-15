from __future__ import annotations

from dataclasses import dataclass, field

from hunter.analysis.semantic.resolver import ResolutionResult


@dataclass
class CFGBlock:
    block_id: str
    function_name: str
    file_rel_path: str
    line: int
    guard_kind: str = "NONE"


@dataclass
class CFGEdge:
    src: str
    dst: str
    kind: str


@dataclass
class CFGResult:
    blocks: list[CFGBlock] = field(default_factory=list)
    edges: list[CFGEdge] = field(default_factory=list)


def build_cfg(resolution: ResolutionResult, *, max_blocks: int = 250_000) -> CFGResult:
    """Builds a deterministic coarse CFG from resolution edges."""
    result = CFGResult()
    fn_to_block: dict[tuple[str, str], str] = {}
    for node in resolution.nodes:
        if len(result.blocks) >= max_blocks:
            break
        block_id = f"bb:{node.file_rel_path}:{node.function_name}:{node.line}"
        fn_to_block[(node.file_rel_path, node.function_name)] = block_id
        result.blocks.append(
            CFGBlock(
                block_id=block_id,
                function_name=node.function_name,
                file_rel_path=node.file_rel_path,
                line=node.line,
            )
        )
    for edge in resolution.edges:
        src = fn_to_block.get((edge.file_rel_path, edge.caller))
        dst = fn_to_block.get((edge.file_rel_path, edge.callee))
        if not src:
            src = f"bb:{edge.file_rel_path}:{edge.caller}:0"
        if not dst:
            dst = f"bb:{edge.file_rel_path}:{edge.callee}:0"
        kind = "NEXT" if edge.resolution_kind == "STATIC" else "UNKNOWN_BRANCH"
        result.edges.append(CFGEdge(src=src, dst=dst, kind=kind))
    result.blocks.sort(key=lambda b: b.block_id)
    result.edges.sort(key=lambda e: (e.src, e.dst, e.kind))
    return result
