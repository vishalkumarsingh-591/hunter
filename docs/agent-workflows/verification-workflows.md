# Verification Workflows

## Ordering
1. **Static alternate analysis** — cheap, safe, deterministic extensions.
2. **Expanded graph queries** — falsification oriented.
3. **Sandbox dynamic** — expensive, tightly controlled last resort.

## Entry Criteria
Hypothesis must include anchors and pass schema validation; sandbox jobs require explicit tenant policy flag.

## Artifact Standards
Artifacts carry type, uri, sha256, retention class. No sensitive customer DB dumps.

## Decision Matrix
| Combination | Result |
|-------------|--------|
| Static confirms + sandbox confirms | `CONFIRMED` |
| Static refutes | `REFUTED` |
| Mixed signals | `INCONCLUSIVE` |

## Failure Handling
Infrastructure errors ≠ security inconclusive — distinct statuses prevent misuse.

## Ethics & Safety
Dynamic flows operate only on synthetic tenants; outbound network disabled unless audited exception recorded.

See `.cursor/pipelines/verification-pipeline.md` and `.cursor/templates/verification-flow-spec.md`.
