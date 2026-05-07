# Confidence Scoring Pipeline

## Objective
Fuse deterministic features and verification outcomes into **transparent** scores.

## Inputs
- Feature snapshots per hypothesis + model registry entry.

## Outputs
- Scores, buckets, explanations, calibration metadata.

## Validation Logic
- Feature completeness checks; missing critical features apply penalties or block external tiers.
- Model version compatibility validation.

## Failure Handling
- If model artifact missing, fall back to conservative heuristic with explicit flag `FALLBACK_MODE`.

## Logging Requirements
Log feature hashes, not raw sensitive code.

## Observability Hooks
Monitor distribution drift of scores; alert on sudden shifts post-deploy.

## Audit Requirements
Store immutable scoring record alongside hypothesis versions.
