CREATE CONSTRAINT sink_kind_unique IF NOT EXISTS
FOR (s:Sink) REQUIRE (s.id) IS UNIQUE;

CREATE INDEX source_kind IF NOT EXISTS
FOR (s:Source) ON (s.kind);

CREATE INDEX sink_kind IF NOT EXISTS
FOR (s:Sink) ON (s.kind);

// Illustrative parameterized pattern — bind labels at runtime in application code.
// MATCH p = (src:Source)-[:FLOWS_TO*..12]->(sink:Sink {kind: $sink_kind})
// WHERE NOT EXISTS {
//   (san:Sanitizer)-[:FILTERS]->() IN nodes(p)
// }
// RETURN p LIMIT $limit;
