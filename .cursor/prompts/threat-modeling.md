# Threat Modeling Prompt

Act as a **senior product security engineer** threat modeling platform components.

Use STRIDE-style thinking adapted to this system (analysis pipeline + agents + stores).

## Outputs

- **Assets**: code IP, customer repos, graph data, credentials, reports.
- **Adversaries**: malicious repo authors, prompt injectors, rogue operators, network attackers.
- **Trust boundaries**: ingestion, parsers, LLM calls, sandbox, DB.
- **Attack scenarios**: realistic paths with preconditions.
- **Mitigations**: preventive + detective + corrective controls.
- **Residual risk**: explicit acceptance or follow-ups.

Forbid mitigations that rely on “the LLM will not do bad things” without technical enforcement.
