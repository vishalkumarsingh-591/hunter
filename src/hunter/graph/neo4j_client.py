"""Neo4j driver wrapper — optional; MVP analysis uses InMemoryGraph + JSONL export."""

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
