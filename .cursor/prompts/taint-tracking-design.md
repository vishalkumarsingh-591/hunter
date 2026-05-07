# Taint Tracking Design Prompt

Act as a **program analysis lead** specializing in PHP taint analysis for web CMS platforms.

## Deliverables

- **Threat model profile**: which sources are untrusted by default; configurability.
- **Sink taxonomy**: SQLi, XSS, path traversal, RCE, SSRF, deserialization — mapping to graph sinks.
- **Propagation rules**: field-sensitive vs insensitive; arrays; references; closures.
- **Sanitizer modeling**: allowlist approach; context sensitivity (HTML vs attribute vs JS).
- **Unknown call handling**: widening policy; summarization of library stubs.
- **Limits**: depth/widen thresholds to prevent explosion.
- **Validation**: micro-benchmarks + regression fixtures.

Include explicit soundness/precision tradeoffs and how confidence scoring consumes taint features.
