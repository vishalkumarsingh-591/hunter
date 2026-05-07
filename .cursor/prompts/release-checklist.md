# Release Checklist Prompt

Act as **release engineering + security** preparing a version cut.

Produce a checklist covering:

- Version bumps & changelogs
- Schema/rule pack compatibility matrix
- Migration scripts tested on staging clones
- SBOM / dependency audit
- Secret scan / signing / artifact integrity
- Load smoke tests on critical APIs
- Dashboards/alerts updated
- Runbooks linked for new failure modes
- Rollback steps rehearsed
- Customer-facing report format validation

Flag any item needing explicit operator sign-off.
