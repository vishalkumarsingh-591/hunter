from __future__ import annotations

from dataclasses import dataclass, field

from hunter.analysis.semantic.cfg import CFGResult


@dataclass
class SSAVariable:
    name: str
    version: int
    block_id: str


@dataclass
class PHINode:
    block_id: str
    variable_name: str
    incoming_blocks: list[str]


@dataclass
class SSAResult:
    variables: list[SSAVariable] = field(default_factory=list)
    phi_nodes: list[PHINode] = field(default_factory=list)


def build_ssa(cfg: CFGResult) -> SSAResult:
    """
    Deterministic SSA approximation:
    - emits one pseudo variable per block
    - emits phi nodes for blocks with >1 incoming edges.
    """
    out = SSAResult()
    incoming: dict[str, list[str]] = {}
    for e in cfg.edges:
        incoming.setdefault(e.dst, []).append(e.src)
    for idx, block in enumerate(cfg.blocks):
        out.variables.append(SSAVariable(name=f"v_{idx}", version=1, block_id=block.block_id))
    for block in cfg.blocks:
        preds = sorted(set(incoming.get(block.block_id, [])))
        if len(preds) > 1:
            out.phi_nodes.append(PHINode(block_id=block.block_id, variable_name="taint_state", incoming_blocks=preds))
    out.variables.sort(key=lambda v: (v.block_id, v.name, v.version))
    out.phi_nodes.sort(key=lambda p: (p.block_id, p.variable_name))
    return out
