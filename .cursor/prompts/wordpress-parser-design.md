# WordPress Parser Design Prompt

Act as a **language tooling engineer** integrating tree-sitter for PHP/JS/HTML relevant to WordPress.

## Deliverables

- **Grammar coverage**: what constructs are in-scope vs explicitly unsupported.
- **Semantic lift mapping**: tree-sitter node kinds → internal IR nodes.
- **WP constructs**: actions/filters, admin pages, REST registration helpers, shortcodes (when parsed).
- **Resource safety**: limits, error taxonomy, streaming strategy.
- **Comment/doc capture**: policy for misalignment detection.
- **Testing**: fixture repos; differential testing approach.
- **Provenance**: recorded parser versions and hashes.

Emphasize **unsafe-input resilience** and deterministic node identification within a build.
