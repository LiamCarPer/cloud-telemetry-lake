"""Pure normalization helpers for GuardDuty findings delivered via EventBridge."""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict

TACTIC_BY_FINDING_PREFIX = {
    "InitialAccess": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "PrivilegeEscalation": "TA0004",
    "DefenseEvasion": "TA0005",
    "CredentialAccess": "TA0006",
    "Discovery": "TA0007",
    "LateralMovement": "TA0008",
    "Collection": "TA0009",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
    "Recon": "TA0043",
    "Reconnaissance": "TA0043",
}


def severity_from_score(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        value = 0.0
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    return "LOW"


def remote_ip(detail: Dict[str, Any]) -> str:
    action = (detail.get("service") or {}).get("action") or {}
    for key in ("awsApiCallAction", "networkConnectionAction", "portProbeAction", "dnsRequestAction"):
        node = action.get(key) or {}
        ip = (node.get("remoteIpDetails") or {}).get("ipAddressV4")
        if ip:
            return ip
    return ""


def normalize_guardduty_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize an EventBridge GuardDuty finding into the shared row shape."""
    detail = event.get("detail") or {}
    resource = detail.get("resource") or {}
    access = resource.get("accessKeyDetails") or {}
    instance = resource.get("instanceDetails") or {}

    finding_type = detail.get("type") or "Unknown"
    score = detail.get("severity", 0)
    prefix = finding_type.split(":", 1)[0]
    tactic = TACTIC_BY_FINDING_PREFIX.get(prefix)

    host = (
        access.get("userName")
        or instance.get("instanceId")
        or resource.get("resourceType")
        or "aws-account"
    )
    user_arn = access.get("principalId") or access.get("userName") or instance.get("instanceId") or "unknown"
    timestamp = (
        detail.get("updatedAt")
        or detail.get("createdAt")
        or event.get("time")
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    reason = "GUARDDUTY_" + re.sub(r"[^A-Za-z0-9]+", "_", finding_type).strip("_").upper()
    description = detail.get("description") or "GuardDuty finding"

    return {
        "timestamp": timestamp,
        "host": host,
        "user_name": access.get("userName") or "",
        "user_arn": user_arn,
        "source_ip": remote_ip(detail),
        "alert_reason": reason,
        "details": f"GuardDuty {finding_type} (severity {score}): {description}",
        "severity": severity_from_score(score),
        "mitre_tactic": tactic,
        "mitre_framework": "enterprise",
        "guardduty_type": finding_type,
        "guardduty_severity": str(score),
        "detection_domain": "identity",
        "raw_line": json.dumps(event, sort_keys=True, default=str),
    }
