"""
report_builder.py – NIST SP 800-61 Incident Response Report Generator

Constructs a structured IR report from a list of detection records
sourced from the ot_detections DynamoDB table. Kept isolated from the
handler to make the report schema independently testable.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Knowledge bases
# ---------------------------------------------------------------------------

RECOMMENDED_ACTIONS: Dict[str, List[str]] = {
    "CROSS_ZONE_VIOLATION": [
        "Isolate the source IP from the OT network segment immediately.",
        "Review and tighten iptables/firewall rules for the Level 3 boundary.",
        "Audit all network sessions between IT and Control zones in the past 24h.",
        "Verify no persistent connections remain across the Purdue model boundary.",
    ],
    "UNAUTHORIZED_MODBUS_WRITE": [
        "Audit all PLC register state changes and roll back unauthorized writes.",
        "Verify physical PLC configuration has not been tampered with.",
        "Enable Modbus function code whitelisting on the OT gateway.",
        "Review Modbus master/slave device list for rogue endpoints.",
    ],
    "OT_BRUTE_FORCE_SCAN": [
        "Block the source IP at the perimeter firewall and OT gateway.",
        "Review OT asset exposure and reduce unnecessary Modbus TCP port accessibility.",
        "Enable rate-limiting on Modbus TCP connections at the gateway level.",
        "Capture and retain full packet capture for forensic analysis.",
    ],
    "PROCESS_SAFETY_VIOLATION": [
        "Halt automated process control and switch to manual operation.",
        "Perform a safety integrity level (SIL) review of the affected process.",
        "Notify the plant safety officer and initiate emergency response procedures.",
    ],
    # Identity / cloud control plane
    "IDENTITY_ROOT_ACCOUNT_USAGE": [
        "Rotate the root credentials and confirm MFA is enabled on the root account.",
        "Review every action performed by the root principal in the last 24 hours.",
        "Check for new access keys, users, roles or trust-policy changes.",
        "Escalate to the account incident process; root use should be exceptional.",
    ],
    "IDENTITY_CONSOLE_LOGIN_WITHOUT_MFA": [
        "Confirm whether the login was expected and whether MFA is enforced for the principal.",
        "Revoke the session and reset the credential if the login is not recognised.",
        "Enforce an MFA-required policy for console access.",
    ],
    "IDENTITY_ACCESS_KEY_CREATED": [
        "Confirm the key creation was authorised and tied to a documented request.",
        "Identify and disable any key that was not expected; rotate the principal's credentials.",
        "Review the new key's activity in CloudTrail and restrict its permissions.",
    ],
    "IDENTITY_IAM_POLICY_MODIFIED": [
        "Compare the policy change with the approved change record.",
        "Revert unexpected privilege grants and review the actor's recent activity.",
        "Check for new principals, trust relationships or persistence mechanisms.",
    ],
    "IDENTITY_CLOUDTRAIL_TAMPERING": [
        "Restore CloudTrail logging immediately if it was stopped or modified.",
        "Preserve existing log files and validate their integrity.",
        "Investigate the actor and source IP; treat this as a defense-evasion event.",
    ],
    "IDENTITY_GUARDDUTY_TAMPERING": [
        "Re-enable GuardDuty and confirm the detector is healthy.",
        "Investigate who changed the detector and what else they touched.",
        "Review findings that may have been suppressed during the gap.",
    ],
    "IDENTITY_CONSOLE_LOGIN_BRUTE_FORCE": [
        "Block or rate-limit the source address and confirm the targeted accounts.",
        "Check whether any attempt succeeded and reset credentials if needed.",
        "Enable account lockout or adaptive authentication for console access.",
    ],
}

GUARDDUTY_ACTIONS: List[str] = [
    "Triage the GuardDuty finding and confirm the affected principal and resource.",
    "Rotate or disable the affected access keys and revoke active sessions.",
    "Review CloudTrail for the same principal and source IP in the preceding 24 hours.",
    "Escalate to the account incident process if the finding indicates active compromise.",
]

MITRE_MAP: Dict[str, str] = {
    "CROSS_ZONE_VIOLATION": "T0886",
    "UNAUTHORIZED_MODBUS_WRITE": "T0831",
    "OT_BRUTE_FORCE_SCAN": "T0846",
    "PROCESS_SAFETY_VIOLATION": "T0835",
    "IPTABLES_DROP": "T0886",  # Firewall-blocked cross-zone traffic maps to Network Connection Enumeration
    # Parser-level rule reasons (the analyzer emits these directly)
    "OT Modbus Write Command": "T0831",
    "OT Siemens S7comm PLC State Change": "T0813",
}

SEVERITY_ORDER: Dict[str, int] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Default incident grouping window. The aggregator reads INCIDENT_WINDOW_SECONDS
# from the environment; this constant keeps the builder usable on its own.
DEFAULT_WINDOW_SECONDS = 300


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_report(detections: List[Dict[str, Any]], window_seconds: int = DEFAULT_WINDOW_SECONDS) -> Dict[str, Any]:
    """
    Constructs a NIST SP 800-61 structured Incident Response report.

    The incident is anchored to a fixed time window derived from the earliest
    event timestamp and `window_seconds`. The incident ID is a deterministic
    UUIDv5 over the window and the sorted detection identities, so a retried
    DynamoDB Streams batch regenerates the *same* report key instead of
    creating a duplicate incident.

    Args:
        detections: List of detection dicts as stored in ot_detections.
        window_seconds: Width of the incident grouping window.

    Returns:
        A fully populated incident report dict ready for JSON serialisation.
    """
    window_seconds = max(int(window_seconds), 1)

    window_start, window_end = _resolve_window(detections, window_seconds)
    incident_id = _derive_incident_id(detections, window_start)
    created_at = datetime.now(timezone.utc).isoformat()

    # Escalate severity to the highest observed across all detections
    highest_severity = _resolve_highest_severity(detections)

    # Collect MITRE ATT&CK techniques by framework (deduplicated, ordered)
    mitre_by_framework = _collect_mitre(detections)
    mitre_techniques = sorted(set(mitre_by_framework["ics"]) | set(mitre_by_framework["enterprise"]))
    mitre_tactics = sorted({
        det.get("mitre_tactic") for det in detections if det.get("mitre_tactic")
    })

    detection_domains = sorted({det.get("detection_domain", "ot") for det in detections})
    identity_count = sum(1 for det in detections if det.get("detection_domain") == "identity")
    ot_count = len(detections) - identity_count

    # Collect affected assets
    hosts = sorted({
        det.get("host", "unknown")
        for det in detections
        if det.get("host")
    })
    source_ips = sorted({
        det.get("src_ip", "")
        for det in detections
        if det.get("src_ip") and det.get("src_ip") != "unknown"
    })

    # Build deduplicated, ordered recommended actions
    recommended_actions = _build_recommended_actions(detections)

    # Sort timeline chronologically by timestamp
    timeline = sorted(detections, key=lambda d: d.get("timestamp", ""))

    return {
        "incident_id": incident_id,
        "created_at": created_at,
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
        "nist_phase": "Detection & Analysis",
        "severity": highest_severity,
        "detection_count": len(detections),
        "detection_domains": detection_domains,
        "ot_detection_count": ot_count,
        "identity_detection_count": identity_count,
        "mitre_techniques": mitre_techniques,
        "mitre_techniques_by_framework": mitre_by_framework,
        "mitre_tactics": mitre_tactics,
        "affected_assets": {
            "hosts": hosts,
            "source_ips": source_ips,
        },
        "timeline": timeline,
        "recommended_actions": recommended_actions,
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _event_time(det: Dict[str, Any]) -> Optional[datetime]:
    """Parse a detection's event timestamp to an aware UTC datetime."""
    for field in ("event_timestamp", "timestamp"):
        raw = det.get(field)
        if not raw or not isinstance(raw, str):
            continue
        # The DynamoDB sort key is "timestamp#event_hash" – keep only the time.
        candidate = raw.split("#", 1)[0].strip()
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _detection_identity(det: Dict[str, Any]) -> str:
    """Stable identity for a single detection, used for incident ID derivation."""
    correlator = str(det.get("incident_correlator", "?"))
    timestamp = str(det.get("timestamp") or det.get("event_timestamp") or "?").split("#", 1)[0]
    return f"{correlator}@{timestamp}"


def _resolve_window(detections: List[Dict[str, Any]], window_seconds: int):
    """Anchor the incident to the window containing the earliest event.

    The end of the window is the configured width or the latest observed event,
    whichever is later, so a multi-minute stream batch never reports an end time
    that excludes its own detections.
    """
    event_times = [t for t in (_event_time(d) for d in detections) if t is not None]
    if not event_times:
        return None, None

    earliest = min(event_times)
    latest = max(event_times)
    anchor_epoch = earliest.timestamp()
    window_start_epoch = int(anchor_epoch // window_seconds) * window_seconds
    window_start = datetime.fromtimestamp(window_start_epoch, tz=timezone.utc)
    window_end = max(window_start + timedelta(seconds=window_seconds), latest)
    return window_start, window_end


def _derive_incident_id(detections: List[Dict[str, Any]], window_start: Optional[datetime]) -> str:
    """Deterministic UUIDv5: same window + same detections => same incident ID."""
    anchor = window_start.isoformat() if window_start else "no-window"
    identities = "|".join(sorted(_detection_identity(d) for d in detections))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"ot-incident:{anchor}:{identities}"))


def _collect_mitre(detections: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Collect ATT&CK techniques separately for ICS and Enterprise workloads."""
    by_framework = {"ics": set(), "enterprise": set()}
    for det in detections:
        technique = det.get("mitre_technique") or MITRE_MAP.get(det.get("alert_reason", ""))
        if not technique:
            continue
        framework = det.get("mitre_framework")
        if not framework:
            framework = "enterprise" if det.get("detection_domain") == "identity" else "ics"
        bucket = "enterprise" if str(framework).lower() in ("enterprise", "identity") else "ics"
        by_framework[bucket].add(str(technique))
    return {key: sorted(values) for key, values in by_framework.items()}


def _resolve_highest_severity(detections: List[Dict[str, Any]]) -> str:
    highest = "LOW"
    for det in detections:
        sev = det.get("severity", "LOW")
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = sev
    return highest


def _build_recommended_actions(detections: List[Dict[str, Any]]) -> List[str]:
    actions: List[str] = []
    seen_types: set = set()
    guardduty_seen = False
    for det in detections:
        alert_type = det.get("alert_reason", "")
        if alert_type and alert_type not in seen_types:
            seen_types.add(alert_type)
            actions.extend(RECOMMENDED_ACTIONS.get(alert_type, []))
            if alert_type.startswith("GUARDDUTY_") and not guardduty_seen:
                guardduty_seen = True
                actions.extend(GUARDDUTY_ACTIONS)
    return actions
