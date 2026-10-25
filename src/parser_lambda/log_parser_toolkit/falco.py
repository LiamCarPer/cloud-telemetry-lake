"""Normalization for Falco runtime events.

Falco owns the runtime rules; this module maps its events into the same
detection/report model used by the audit and cloud planes.
"""

import json
import re
from typing import Any, Dict, Optional

PRIORITY_SEVERITY = {
    "emergency": "HIGH",
    "alert": "HIGH",
    "critical": "HIGH",
    "error": "MEDIUM",
    "warning": "MEDIUM",
    "notice": "LOW",
    "informational": "LOW",
    "info": "LOW",
    "debug": "LOW",
}

# (substring in rule name, technique, tactic, severity override)
RULE_MAPPINGS = [
    ("terminal shell", "T1609", "TA0002", "HIGH"),
    ("shell in container", "T1609", "TA0002", "HIGH"),
    ("privileged", "T1611", "TA0004", "HIGH"),
    ("read sensitive file", "T1552", "TA0006", "HIGH"),
    ("sensitive file", "T1552", "TA0006", "HIGH"),
    ("crypto", "T1496", "TA0040", "HIGH"),
    ("mining", "T1496", "TA0040", "HIGH"),
    ("package management", "T1610", "TA0002", "MEDIUM"),
]


def _field(event: Dict[str, Any], *names: str) -> str:
    fields = event.get("output_fields") or {}
    if not isinstance(fields, dict):
        return ""
    for name in names:
        value = fields.get(name)
        if value not in (None, ""):
            return str(value)
    return ""


def normalize_falco_event(event: Dict[str, Any]) -> Dict[str, Any]:
    rule = event.get("rule") or "Unknown Falco rule"
    priority = str(event.get("priority") or "").lower()
    fields = event.get("output_fields") or {}

    technique: Optional[str] = None
    tactic: Optional[str] = None
    severity = PRIORITY_SEVERITY.get(priority, "LOW")
    lower_rule = rule.lower()
    for needle, candidate_technique, candidate_tactic, candidate_severity in RULE_MAPPINGS:
        if needle in lower_rule:
            technique = candidate_technique
            tactic = candidate_tactic
            severity = candidate_severity
            break

    namespace = _field(event, "k8s.ns.name", "ka.target.namespace")
    pod = _field(event, "k8s.pod.name", "ka.target.name")
    container = _field(event, "container.name", "container.id")
    host = pod or event.get("hostname") or container or "kubernetes"
    reason = "FALCO_" + re.sub(r"[^A-Za-z0-9]+", "_", rule).strip("_").upper()

    return {
        "timestamp": event.get("time", ""),
        "host": host,
        "namespace": namespace,
        "pod": pod,
        "container": container,
        "process": _field(event, "proc.name"),
        "command": _field(event, "proc.cmdline"),
        "file": _field(event, "fd.name"),
        "user": _field(event, "user.name"),
        "source_ip": _field(event, "fd.sip", "evt.addr", "k8s.pod.ip"),
        "alert_reason": reason,
        "details": f"Falco [{event.get('priority')}] {rule}: {event.get('output', '')}",
        "severity": severity,
        "mitre_technique": technique,
        "mitre_framework": "containers",
        "mitre_tactic": tactic,
        "falco_rule": rule,
        "falco_priority": event.get("priority", ""),
        "detection_domain": "kubernetes",
        "raw_line": json.dumps(event, sort_keys=True, default=str),
    }
