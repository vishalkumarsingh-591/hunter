# Agent Philosophy

## Role of Agents
Agents **compress and contextualize** large deterministic artifacts for humans and downstream scoring. They **prioritize hypotheses**, never replace graph truth.

## Minimal Agency
Tools are narrow, typed, and audited. Budgets (time/tokens/calls) are mandatory. No open-ended “run shell” tools in production configurations.

## Separation of Concerns
- **Extraction**: facts only.
- **Analyst**: interprets within evidence boundaries.
- **Skeptic**: seeks falsification.
- **Verification**: empirical checks under policy.
- **Confidence**: fuses features transparently.
- **Reporting**: formats; does not invent.

## Structured Epistemology
Outputs are schema-validated objects referencing evidence ids. Natural language is optional rendering.

## Debate as Defense in Depth
Disagreement is an asset; consensus requires passing explicit gates for sensitive tiers.

## Prompt Injection Awareness
Repository content is hostile input to prompts; separate policy layers from data layers.

## Human Partnership
Automation escalates; humans retain accountability for external assertions.
