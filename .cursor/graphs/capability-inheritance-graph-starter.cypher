CREATE CONSTRAINT role_name_unique IF NOT EXISTS
FOR (r:Role) REQUIRE (r.name, r.dataset_version) IS NODE KEY;

CREATE CONSTRAINT cap_name_unique IF NOT EXISTS
FOR (c:Capability) REQUIRE c.name IS UNIQUE;

// Example: handlers asserting manage_options
// MATCH (e:Entrypoint)-[:REQUIRES]->(c:Capability {name:'manage_options'})
// RETURN e, c;
