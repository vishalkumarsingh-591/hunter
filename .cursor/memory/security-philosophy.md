# Security Philosophy

## Defensive Primacy
Features exist to **reduce risk for defenders**, not to enable covert offensive campaigns.

## Assume Malicious Inputs
Repositories are untrusted: parsers, zip handlers, and graph importers must be resilient.

## Least Privilege Everywhere
Services, DB roles, operators, and agents each receive minimum permissions.

## Strong Boundaries
Tenant isolation, sandboxed dynamic verification, default-deny egress on execution environments.

## Cryptographic Hygiene
Use standard libraries; enforce TLS; rotate keys; avoid bespoke protocols.

## AI Is Part of the Threat Surface
Models can be manipulated by content in repos (prompt injection). Treat LLM outputs as untrusted until validated and anchored.

## Transparency Supports Defense
Audit logs and explainable evidence speed incident response and deter insider misuse.

## Responsible Capability
Capabilities approaching exploitation require explicit purpose-bound environments, approvals, and logging.

## Continuous Assurance
Threat models and tests evolve with the codebase — security is not a gate at the end.
