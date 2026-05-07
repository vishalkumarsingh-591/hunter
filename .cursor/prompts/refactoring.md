# Refactoring Prompt

Plan a refactor as a **staff engineer** prioritizing safety and modularity.

## Requirements

- Map current vs target module boundaries; list moved responsibilities.
- Preserve public contracts or provide migration steps.
- Identify risk hotspots (parsers, graph migrations, auth).
- Testing plan: incremental commits, compatibility shims duration.
- Performance impact assessment.
- Rollback plan.

Refactors must not hide agent logic or weaken verification gates.
