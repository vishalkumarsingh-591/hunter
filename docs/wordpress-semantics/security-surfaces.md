# WordPress Security Surfaces

## Unauthenticated Web
- Public pages and filters may process query parameters and cookies.
- **REST API** routes with permissive `permission_callback` values are high interest.

## Authenticated Surfaces
- `admin-ajax.php` actions including `wp_ajax_nopriv_*` may bridge trust boundaries.
- Admin post handlers require CSRF nonces for state change — model nonce pairing.

## Capabilities & Roles
Static extraction maps literals to capabilities; dynamic computation yields uncertainty requiring skeptic attention.

## Metadata Stores
Options, post meta, user meta can become surprising sources when low-privilege roles influence values — configurable profiles encode assumptions.

## Hooks & Filters
Callbacks may alter queries or capabilities; unresolved callbacks widen graphs conservatively.

## Remote Calls
`wp_remote_*` sinks enable SSRF reasoning when URLs derive partially from user input.

## Modeling Guidance
Prefer **explicit uncertainty nodes** over silent omission when WordPress dynamics prevent proof.

## Ethics
Focus findings on enabling remediation; avoid exploit-centric narratives in automated outputs.
