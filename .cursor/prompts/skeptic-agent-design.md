# Skeptic Agent Design Prompt

Design the **Skeptic Agent** to adversarially critique analyst hypotheses.

Include:

- Counterevidence search strategies over graph slices (alternate paths, missing capability checks).
- Prompt injection defenses when reading untrusted code excerpts.
- Structured output: `{critique[], falsifying_paths[], alternate_hypotheses[], confidence_impact}`.
- Rules for when skeptic can **block promotion** vs merely downgrade confidence.
- Evidence requirements — skeptic claims must reference ids/paths too.

The skeptic must assume **good faith but fallible** upstream agents.
