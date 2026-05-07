# Platform Threat Model (Starter)

## Assets
- Customer source code confidentiality.
- Graph/query intellectual property.
- Credentials & tokens for SaaS deployment (future).
- Integrity of published vulnerability reports.

## Trust Boundaries
1. **External operator → API**
2. **API → workers**
3. **Workers → parsers/graph**
4. **Agents → tools/datastores**
5. **Sandbox → external network** (must be tightly controlled)

## Adversaries
- Malicious repository authors (zip bombs, parser exploits, prompt injection via comments).
- Prompt injection against agents consuming repo text.
- Rogue insiders escalating privileges via misconfigured RBAC.
- Network attackers targeting exposed APIs (future internet-facing deployments).

## Representative Scenarios
| Scenario | Preconditions | Impact | Mitigations |
|---------|----------------|--------|-------------|
| Archive zip-slip | Malicious tarball uploaded | Host compromise during ingest | Strict extractor, permissions |
| Graph injection via crafted PHP | Parser succeeds | Incorrect findings | Deterministic validation, skeptic |
| SSRF via verification misconfig | Policy mis-set | Lateral movement | Default deny egress, approvals |

## Residual Risks
Undecidable static facts remain; platform communicates uncertainty rather than false certainty.

## Maintenance
Update this document when adding dynamic verification, multi-tenant SaaS, or external integrations.
