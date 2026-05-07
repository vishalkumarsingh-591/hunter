# Verification Agent Design Prompt

Design the **Verification Agent** responsible for corroborating/refuting candidates.

Cover:

- Preconditions for dynamic verification (policy, sandbox image version).
- Static corroboration-first ordering.
- Artifact schema (`confirmed/refuted/inconclusive`).
- Resource caps and watchdog behavior.
- Logging & trace correlation.
- Integration with skeptic outputs — how contradictions are resolved without silent severity bumps.
- Forbidden actions (external scanning, credential stuffing, etc.).

Emphasize **defensive proof**, not exploit optimization.
