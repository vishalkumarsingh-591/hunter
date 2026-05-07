from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class InMemoryGraph:
    """Primary analysis graph for PART 1 when Neo4j is disabled; exportable to JSONL."""

    snapshot_id: str
    schema_version: str
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def upsert_node(self, nid: str, label: str, props: dict[str, Any]) -> None:
        row = {"id": nid, "label": label, **props}
        self.nodes[nid] = row

    def add_edge(self, src: str, rel: str, dst: str, props: dict[str, Any] | None = None) -> str:
        eid = f"e:{src}:{rel}:{dst}:{len(self.edges)}"
        self.edges.append({"id": eid, "src": src, "rel": rel, "dst": dst, **(props or {})})
        return eid

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
        with open(rels_path, "w", encoding="utf-8") as rout:
            for e in self.edges:
                rout.write(json.dumps(e, sort_keys=True) + "\n")
        (out_dir / "snapshot_id.txt").write_text(self.snapshot_id, encoding="utf-8")
        (out_dir / "schema_version.txt").write_text(self.schema_version, encoding="utf-8")
