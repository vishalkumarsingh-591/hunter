"""Pinned grammar / lift revisions for replay_token."""

from __future__ import annotations

import hashlib

# Bump when IR lift logic changes (not only grammar patch versions).
LIFT_VERSION = "1"

# PyPI grammar package versions at time of lock — informational.
GRAMMAR_REVISIONS = {
    "tree-sitter-php": "0.22.x",
    "tree-sitter-javascript": "0.21.x",
    "tree-sitter-html": "0.20.x",
}


def grammar_lock_hash() -> str:
    payload = f"{LIFT_VERSION}|{sorted(GRAMMAR_REVISIONS.items())}".encode()
    return hashlib.sha256(payload).hexdigest()[:16]
