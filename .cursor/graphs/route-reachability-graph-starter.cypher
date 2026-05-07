CREATE INDEX httproute_path IF NOT EXISTS
FOR (r:HttpRoute) ON (r.path_template);

CREATE INDEX ajax_action IF NOT EXISTS
FOR (a:AjaxAction) ON (a.action_name);

// Example: nopriv ajax actions
// MATCH (a:AjaxAction {nopriv:true})-[:HANDLED_BY]->(fn:Symbol)
// RETURN a, fn LIMIT 100;
