"""Severity registry shared by the OT and identity detection planes."""

from typing import Dict

# Declarative severity registry mapping alert reasons to severity levels.
SEVERITY_MAPPING: Dict[str, str] = {
    # OT / network
    "SSH Brute Force": "HIGH",
    "Windows Brute Force": "HIGH",
    "OT Siemens S7comm PLC State Change": "HIGH",
    "Known Malicious IP": "HIGH",
    "CROSS_ZONE_VIOLATION": "HIGH",
    "OT_BRUTE_FORCE_SCAN": "HIGH",
    "Privilege Escalation": "MEDIUM",
    "OT Modbus Write Command": "MEDIUM",
    "UNAUTHORIZED_MODBUS_WRITE": "MEDIUM",
    "Web Directory Scanning": "MEDIUM",
    # Identity / cloud control plane
    "IDENTITY_ROOT_ACCOUNT_USAGE": "HIGH",
    "IDENTITY_CONSOLE_LOGIN_WITHOUT_MFA": "HIGH",
    "IDENTITY_ACCESS_KEY_CREATED": "HIGH",
    "IDENTITY_IAM_POLICY_MODIFIED": "HIGH",
    "IDENTITY_CLOUDTRAIL_TAMPERING": "HIGH",
    "IDENTITY_GUARDDUTY_TAMPERING": "HIGH",
    "IDENTITY_CONSOLE_LOGIN_BRUTE_FORCE": "MEDIUM",
}


def get_severity(alert_reason: str) -> str:
    """Resolves alert severity from the registry with a LOW fallback."""
    return SEVERITY_MAPPING.get(alert_reason, "LOW")
