CREATE INDEX basicblock_fn IF NOT EXISTS
FOR (b:BasicBlock) ON (b.function_fqn);

// Example reachability skeleton (requires populated NEXT edges)
// MATCH (fn:Symbol {kind:'FUNCTION', fqn:$fqn})-[:ENTRY]->(entry:BasicBlock)
// MATCH (sink:Callsite {id:$sink_id})-[:LOCATED_IN]->(bb:BasicBlock)
// MATCH p = shortestPath((entry)-[:NEXT|TRUE_BRANCH|FALSE_BRANCH*..200]->(bb))
// RETURN p;
