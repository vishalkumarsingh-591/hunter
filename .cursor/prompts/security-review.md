# Security Review Prompt

Perform a **focused security review** of the described component or change.

## Method

- Map trust boundaries and data flows.
- Identify realistic exploit paths (not theoretical lint).
- Check authn/authz, injection, SSRF, deserialization, path traversal, insecure crypto, logging leaks.
- Evaluate AI-specific risks: prompt injection, tool misuse, overtrust of model outputs.

## Output

For each finding: **title**, **severity**, **likelihood**, **impact**, **evidence**, **remediation**, **tests** to prevent regression.

Align severity with enterprise disclosure norms; avoid noise.
