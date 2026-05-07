# Taint Analysis Specification: <Engine Version>

## 1. Threat Model Profile
- **Untrusted sources**:
- **Trusted assumptions documented**:

## 2. Source & Sink Definitions
- **Sources** (graph predicates):
- **Sinks** (graph predicates):

## 3. Propagation Rules
- **Assignments / calls / returns / fields / arrays**:
- **PHP-specific features** (references, compact/extract, globals):

## 4. Sanitizer & Validator Catalog
- **Modeled functions**:
- **Context matrix** (sink context vs required sanitizer):

## 5. Unknown / Dynamic Resolution
- **Widening policy**:
- **Stub strategy**:

## 6. Limits & Widening
- **Depth / worklist caps**:
- **Cycle handling**:

## 7. Outputs
- **Per-path summaries**:
- **Feature vector for confidence engine**:

## 8. Testing
- **Micro-fixtures**:
- **Known limitations**:

## 9. Observability
- **Metrics for blow-ups / timeouts**:
