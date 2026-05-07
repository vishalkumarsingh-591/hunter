# Taint Analysis Methodology

## Objectives
Track **untrusted data** from defined **sources** to **sinks** with explicit modeling of **sanitizers** and **contexts** (SQL vs HTML attribute vs inline JS).

## Configuration
Threat profiles label which superglobals, meta keys, and REST fields are untrusted. Defaults are conservative for public research tenants.

## Propagation
The engine expands along dataflow edges with field sensitivity where implemented. PHP references and dynamic includes widen states explicitly.

## Sanitizers
Only sanitizer functions with encoded semantics participate in removing taint for a given context. Unknown functions do not clear taint.

## CFG Integration
When execution graphs exist, only **feasible** path witnesses count toward confidence. Unreachable sanitizers are flagged as non-mitigating.

## Outputs
Machine-readable path bundles feed the **confidence engine**; agents never replace these witnesses, only explain them.

## Testing
Micro-fixtures target tricky flows; regression tests lock expected path presence/absence.

## Limitations
Dynamic property names, `eval`, and unbounded plugin indirection may force **INCONCLUSIVE** — an honest outcome.
