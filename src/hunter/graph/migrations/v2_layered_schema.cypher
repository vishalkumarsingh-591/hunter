// Layered schema v2 (compatible with PART 1 exports).
CREATE CONSTRAINT snapshot_unique_v2 IF NOT EXISTS
FOR (s:Snapshot) REQUIRE s.id IS UNIQUE;

CREATE CONSTRAINT file_scoped_unique_v2 IF NOT EXISTS
FOR (f:File) REQUIRE (f.snapshot_id, f.path) IS NODE KEY;

CREATE INDEX symbol_scoped_fqn_v2 IF NOT EXISTS
FOR (s:Symbol) ON (s.snapshot_id, s.fqn);

CREATE INDEX callsite_scoped_id_v2 IF NOT EXISTS
FOR (c:Callsite) ON (c.snapshot_id, c.callsite_id);

CREATE INDEX taint_region_scoped_id_v2 IF NOT EXISTS
FOR (t:TaintRegion) ON (t.snapshot_id, t.region_id);

CREATE INDEX security_motif_scoped_id_v2 IF NOT EXISTS
FOR (m:SecurityMotif) ON (m.snapshot_id, m.motif_id);
