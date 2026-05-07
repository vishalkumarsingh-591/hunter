# Reporting Pipeline Design Prompt

Design the **reporting pipeline** from finalized findings to exports.

Specify:

- Inputs (finding records, evidence bundles, build metadata).
- Output formats (Markdown/HTML/PDF path + JSON schema).
- Redaction rules for secrets and PII.
- Signing/integrity optional path.
- Human review gates for high severity.
- Archival & retention policies.
- Reproducibility appendix contents.

Ensure machine-readable outputs remain **strictly derived** from stored evidence, not freeform model narration.
