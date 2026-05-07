# Architecture Principles

## Deterministic Analysis First
Probabilistic components assist; they do not define ground truth. Every finding must trace to deterministic artifacts (AST nodes, graph paths, rule evaluations).

## Knowledge Graph as Contracted Truth
Neo4j encodes relationships the platform agrees exist; agents consume projections, not raw filesystem guesses.

## Evidence-Driven Outputs
Reports are compilations of verified subgraphs and checks; narrative without handles is invalid for external publication tiers.

## Skepticism Built-In
High-impact claims require adversarial review (automated skeptic agent + human policy).

## Modular Pipelines
Stages communicate via versioned DTOs and explicit queues/commands — no hidden shared mutable singletons for core logic.

## Secure Defaults
Sandboxes default closed; APIs default deny; parsers default bounded.

## Observability Everywhere
Each stage emits correlation-aware telemetry suitable for SRE workflows.

## Reproducibility
Immutable build inputs (commit SHA, lockfiles, rule pack hash) accompany every published assessment.

## Explainability Over Automation Vanity
Prefer transparent traversals and provenance to opaque “model said so” reasoning.

## Evolution Without Fragility
Schema migrations are first-class; backward compatibility or explicit upgrade paths required.
