from __future__ import annotations

import re

_RULE_TYPE = re.compile(r"^RULE-([A-Z0-9]+)-")


def vuln_type_from_rule(rule_id: str) -> str:
    m = _RULE_TYPE.match(rule_id or "")
    if m:
        return m.group(1)
    if rule_id.startswith("RULE-WP-"):
        return "WP"
    return "OTHER"


def title_from_rule(rule_id: str) -> str:
    vt = vuln_type_from_rule(rule_id)
    labels = {
        "SQLI": "SQL Injection",
        "XSS": "Cross-Site Scripting",
        "REDIRECT": "Open Redirect",
        "LFI": "Local File Inclusion",
        "RFI": "Remote File Inclusion",
        "RCE": "Remote Code Execution",
        "UPLOAD": "Unsafe File Upload",
        "SSRF": "Server-Side Request Forgery",
        "CSV": "CSV Injection",
        "OBJINJ": "Object Injection",
        "WP": "WordPress Security",
    }
    return labels.get(vt, rule_id)
