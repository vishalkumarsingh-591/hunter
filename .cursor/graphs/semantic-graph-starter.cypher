// Starter constraints & indexes — adapt labels/property names to your migrations.
// Execute via Neo4j migration tooling, not ad hoc in production.

CREATE CONSTRAINT repo_id_unique IF NOT EXISTS
FOR (r:Repository) REQUIRE r.id IS UNIQUE;

CREATE CONSTRAINT commit_sha_unique IF NOT EXISTS
FOR (c:Commit) REQUIRE c.sha IS UNIQUE;

CREATE CONSTRAINT file_path_per_repo_commit IF NOT EXISTS
FOR (f:File) REQUIRE (f.repo_id, f.commit_sha, f.path) IS NODE KEY;

CREATE INDEX file_language IF NOT EXISTS
FOR (f:File) ON (f.language);

CREATE INDEX symbol_fqn IF NOT EXISTS
FOR (s:Symbol) ON (s.fqn);

// Example motif: unresolved dynamic call near sink (pattern skeleton)
// MATCH (sink:Symbol {kind: 'SINK_SQL'})
// MATCH (call:Callsite)-[:INVOKES_UNRESOLVED]->(:UnknownTarget)
// WHERE EXISTS { (call)-[:DATAFLOW*..6]->(sink) }
// RETURN call, sink LIMIT 25;
