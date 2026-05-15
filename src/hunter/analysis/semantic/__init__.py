from hunter.analysis.semantic.cfg import build_cfg
from hunter.analysis.semantic.diff import compute_semantic_diff
from hunter.analysis.semantic.resolver import build_interprocedural_resolution
from hunter.analysis.semantic.ssa import build_ssa

__all__ = [
    "build_cfg",
    "build_interprocedural_resolution",
    "build_semantic_diff",
    "build_ssa",
]


def build_semantic_diff(*args, **kwargs):
    return compute_semantic_diff(*args, **kwargs)
