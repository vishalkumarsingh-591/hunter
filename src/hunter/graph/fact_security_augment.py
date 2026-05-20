"""Backward-compatible re-exports; logic lives in security_facts_catalog."""

from hunter.graph.security_facts_catalog import connect_same_file_flows

__all__ = ["connect_same_file_flows"]
