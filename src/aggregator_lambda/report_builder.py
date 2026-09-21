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
}

MITRE_MAP: Dict[str, str] = {
    "CROSS_ZONE_VIOLATION": "T0886",
    "UNAUTHORIZED_MODBUS_WRITE": "T0831",
    "OT_BRUTE_FORCE_SCAN": "T0846",
    "PROCESS_SAFETY_VIOLATION": "T0835",
    "IPTABLES_DROP": "T0886",  # Firewall-blocked cross-zone traffic maps to Network Connection Enumeration
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

    # Collect MITRE ATT&CK for ICS techniques (deduplicated, ordered, valid only)
    mitre_techniques = sorted({
        MITRE_MAP[det.get("alert_reason", "")]
        for det in detections
        if det.get("alert_reason") and det.get("alert_reason") in MITRE_MAP
    })

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
        "mitre_techniques": mitre_techniques,
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
    """Anchor the incident to the fixed window containing the earliest event."""
    event_times = [t for t in (_event_time(d) for d in detections) if t is not None]
    if not event_times:
        return None, None

    anchor_epoch = min(event_times).timestamp()
    window_start_epoch = int(anchor_epoch // window_seconds) * window_seconds
    window_start = datetime.fromtimestamp(window_start_epoch, tz=timezone.utc)
    return window_start, window_start + timedelta(seconds=window_seconds)


def _derive_incident_id(detections: List[Dict[str, Any]], window_start: Optional[datetime]) -> str:
    """Deterministic UUIDv5: same window + same detections => same incident ID."""
    anchor = window_start.isoformat() if window_start else "no-window"
    identities = "|".join(sorted(_detection_identity(d) for d in detections))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"ot-incident:{anchor}:{identities}"))


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
    for det in detections:
        alert_type = det.get("alert_reason", "")
        if alert_type and alert_type not in seen_types:
            seen_types.add(alert_type)
            actions.extend(RECOMMENDED_ACTIONS.get(alert_type, []))
    return actions
