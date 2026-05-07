# Confidence Scoring

## Principles
Confidence expresses **epistemic certainty given observable evidence**, not model bravado.

## Inputs (Illustrative Categories)
- Taint path specificity (length, context alignment).
- Presence/absence of sanitizers matching sink contexts.
- CFG guard witnesses vs unresolved dynamic calls.
- Trust-boundary classification certainty.
- Historical false positive rate for rule family (versioned table).
- Verification outcomes (`CONFIRMED`, `REFUTED`, `INCONCLUSIVE`).

## Model Discipline
- Use interpretable models first; complex models require documentation and monitoring.
- Calibrate on labeled sets; version models independently from rule packs.

## Thresholds
Configure environment-specific gates:
- **Internal triage** may show low-threshold items.
- **External customer reports** require higher thresholds and human review for top severities.

## Explanations
Each score exports top positive/negative features with magnitudes to support human audit.

## Anti-Patterns
- LLM token probabilities as confidence.
- Raising confidence solely because multiple agents “agree” without new evidence.

See `.cursor/pipelines/confidence-scoring-pipeline.md` and `.cursor/memory/graph-philosophy.md`.
