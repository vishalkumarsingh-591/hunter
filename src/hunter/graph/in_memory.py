from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _stable_edge_id(src: str, rel: str, dst: str, props: dict[str, Any] | None) -> str:
    canonical = json.dumps(props or {}, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(f"{src}\0{rel}\0{dst}\0{canonical}".encode()).hexdigest()[:16]
    return f"e:{digest}"


@dataclass
class InMemoryGraph:
    """Primary analysis graph for PART 1 when Neo4j is disabled; exportable to JSONL."""

    snapshot_id: str
    schema_version: str
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)
    _edge_ids: set[str] = field(default_factory=set, repr=False)

    def upsert_node(self, nid: str, label: str, props: dict[str, Any]) -> None:
        row = {"id": nid, "label": label, **props}
        self.nodes[nid] = row

    def add_edge(self, src: str, rel: str, dst: str, props: dict[str, Any] | None = None) -> str:
        eid = _stable_edge_id(src, rel, dst, props)
        if eid in self._edge_ids:
            return eid
        self._edge_ids.add(eid)
        self.edges.append({"id": eid, "src": src, "rel": rel, "dst": dst, **(props or {})})
        return eid

    def bulk_add(
        self,
        nodes: dict[str, dict[str, Any]],
        edges: list[tuple[str, str, str, dict[str, Any] | None]],
    ) -> None:
        for nid, row in nodes.items():
            label = str(row.get("label", "Node"))
            props = {k: v for k, v in row.items() if k not in ("id", "label")}
            self.upsert_node(nid, label, props)
        for src, rel, dst, props in edges:
            self.add_edge(src, rel, dst, props)

    def neighbors(self, nid: str, rel: str | None = None, direction: str = "out") -> Iterator[tuple[str, str, str]]:
        for e in self.edges:
            if rel and e["rel"] != rel:
                continue
            if direction == "out" and e["src"] == nid:
                yield e["src"], e["rel"], e["dst"]
            if direction == "in" and e["dst"] == nid:
                yield e["src"], e["rel"], e["dst"]

    def export_jsonl(self, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        nodes_path = out_dir / "nodes.jsonl"
        rels_path = out_dir / "rels.jsonl"
        with open(nodes_path, "w", encoding="utf-8") as nout:
            for nid in sorted(self.nodes):
                nout.write(json.dumps(self.nodes[nid], sort_keys=True) + "\n")
        sorted_edges = sorted(self.edges, key=lambda e: (e["src"], e["rel"], e["dst"], e["id"]))
        with open(rels_path, "w", encoding="utf-8") as rout:
            for e in sorted_edges:
                rout.write(json.dumps(e, sort_keys=True) + "\n")
        (out_dir / "snapshot_id.txt").write_text(self.snapshot_id, encoding="utf-8")
        (out_dir / "schema_version.txt").write_text(self.schema_version, encoding="utf-8")
