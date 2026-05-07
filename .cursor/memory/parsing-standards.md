# Parsing Standards

## Coverage Goal
Parse **every text file** intended for analysis within declared languages; skipped files must be explicit (`UNSUPPORTED_ENCODING`, `BINARY`, `SIZE_EXCEEDED`, etc.).

## Canonical Metadata Per File
- `path`, `language_guess`, `parser_language`, `sha256`, `byte_length`
- `tree_sitter_version`, `grammar_revisions`
- `parse_status`, `diagnostics[]`

## Offsets & Snippets
Store UTF-8 byte offsets + line/column for navigation; snippets are derived with caps to avoid memory blowups.

## Error Taxonomy
Distinguish **lexer errors**, **timeout**, **too_deep**, **too_many_nodes**, **grammar_gap**.

## Incremental Parse Strategy (Future)
Design for reparsing changed files per commit while reusing unchanged subgraph pointers.

## Comment Handling
Associate comments with nearest AST nodes; flag **doc vs implementation** mismatches only as low-severity informational candidates unless rules define otherwise.

## Security
Never execute code during parse. Disable dangerous native extensions. Validate archive extraction paths to prevent zip-slip.

## Testing Requirements
Each grammar bump requires regression fixtures including WP idioms (`add_action`, anonymous callbacks, namespaces).
