CREATE INDEX entrypoint_route IF NOT EXISTS
FOR (e:Entrypoint) ON (e.route_template);

// Example pattern: entrypoint without resolved capability guard
// MATCH (e:Entrypoint)-[:IN_ZONE]->(z:TrustZone {name:'PUBLIC_HTTP'})
// WHERE NOT EXISTS { (e)-[:PROTECTED_BY]->(:CapabilityCheck) }
// MATCH (e)-[:ACCESSES]->(a:Asset)
// RETURN e, a LIMIT 50;
