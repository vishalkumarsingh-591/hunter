from __future__ import annotations

from dataclasses import dataclass

from hunter.graph.in_memory import InMemoryGraph

LAYER0 = "L0_REPOSITORY"
LAYER1 = "L1_SEMANTIC"
LAYER2 = "L2_WORDPRESS"
LAYER3 = "L3_FEATURE_FLOW"
LAYER4 = "L4_SECURITY"


@dataclass(frozen=True)
class LayeringResult:
    layered_nodes: int
    layered_edges: int


def infer_layer(label: str, rel: str | None = None) -> str:
    if label in {"Repository", "Snapshot", "File"}:
        return LAYER0
    if label in {
        "IRNode",
        "Symbol",
        "Callsite",
        "Class",
        "UnknownTarget",
        "ResolutionNode",
        "Function",
        "Method",
        "HookHandler",
        "AjaxHandler",
    }:
        return LAYER1
    if label in {"HookRegistration", "Route", "AjaxAction", "CapabilityCheck", "NonceGuardApprox"}:
        return LAYER2
    if label in {"CFGBlock", "SSAVariable", "PHINode", "Source", "Sanitizer", "HeuristicPattern"}:
        return LAYER3
    if label in {"Sink", "SecuritySignal", "VariantCluster"}:
        return LAYER4
    if rel in {"FLOWS_TO", "TAINTS", "CAN_REACH_SINK", "PROTECTS", "ANCHORED_AT"}:
        return LAYER3
    return LAYER1


def apply_layers(g: InMemoryGraph) -> LayeringResult:
    for node in g.nodes.values():
        node["layer"] = infer_layer(str(node.get("label", "")))
    for edge in g.edges:
        src = g.nodes.get(edge["src"], {})
        dst = g.nodes.get(edge["dst"], {})
        src_layer = src.get("layer")
        dst_layer = dst.get("layer")
        edge["layer_src"] = src_layer
        edge["layer_dst"] = dst_layer
        edge["layer"] = dst_layer or src_layer or infer_layer("", str(edge.get("rel")))
    return LayeringResult(layered_nodes=len(g.nodes), layered_edges=len(g.edges))
