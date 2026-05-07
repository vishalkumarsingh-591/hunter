# Incident Response Playbook

## Severity Levels (Illustrative)
- **SEV1**: Active data breach, sandbox escape, widespread auth bypass.
- **SEV2**: Partial outage, integrity risk without confirmed exfiltration.
- **SEV3**: Limited degradation, workaround exists.

## Roles
- **Incident Commander**, **Communications**, **Technical Lead**, **Scribe**.

## Steps (Compressed)
1. **Declare incident** — channel + ticket + timestamp.
2. **Contain** — disable affected feature flags, revoke tokens, isolate sandboxes.
3. **Eradicate** — patch root cause; verify no persistence.
4. **Recover** — restore services with monitoring uplift.
5. **Post-incident review** — blameless, action items with owners.

## Evidence Handling
Preserve logs immutably; restrict access; legal/compliance notification per policy.

## Customer Comms Template
Follow `.cursor/templates/incident-report.md` internally; external notice separate.

## Drills
Quarterly tabletop covering malicious repo upload + agent prompt injection scenarios.
