"""Neo4j driver wrapper — optional persistence only (schema meta today).

Bulk graph MERGE and vector search are deferred: use InMemoryGraph + JSONL for analysis;
use a dedicated vector store (e.g. Qdrant) for embeddings in a later milestone.
"""

from __future__ import annotations

from hunter.logging import get_logger

_LOG = get_logger("hunter.graph.neo4j")


def try_write_schema_meta(uri: str, user: str, password: str, snapshot_id: str, schema_version: str) -> bool:
    if not uri:
        return False
    try:
        from neo4j import GraphDatabase

        drv = GraphDatabase.driver(uri, auth=(user, password))
        with drv.session() as session:
            session.run(
                "MERGE (m:SchemaMeta {snapshot_id: $sid}) SET m.schema_version = $v",
                sid=snapshot_id,
                v=schema_version,
            )
        drv.close()
        _LOG.info("neo4j_schema_meta_written", snapshot_id=snapshot_id)
        return True
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("neo4j_unavailable", error=str(exc))
        return False


def try_bulk_write_graph(
    uri: str,
    user: str,
    password: str,
    g: object,
    *,
    batch_size: int = 500,
    max_nodes: int = 50_000,
) -> bool:
    """Optional batched MERGE of in-memory graph nodes (feature-flagged)."""
    if not uri:
        return False
    from hunter.graph.in_memory import InMemoryGraph

    if not isinstance(g, InMemoryGraph):
        return False
    try:
        from neo4j import GraphDatabase

        drv = GraphDatabase.driver(uri, auth=(user, password))
        nodes = list(g.nodes.items())[:max_nodes]
        with drv.session() as session:
            for i in range(0, len(nodes), batch_size):
                batch = nodes[i : i + batch_size]
                for nid, props in batch:
                    label = str(props.get("label", "Node"))
                    safe_label = "".join(c if c.isalnum() else "_" for c in label) or "Node"
                    session.run(
                        f"MERGE (n:`{safe_label}` {{id: $id}}) SET n += $props",
                        id=nid,
                        props={k: v for k, v in props.items() if k != "label"},
                    )
        drv.close()
        _LOG.info("neo4j_bulk_write_complete", nodes=min(len(nodes), max_nodes))
        return True
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("neo4j_bulk_write_failed", error=str(exc))
        return False
