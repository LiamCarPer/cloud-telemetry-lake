"""Identity detection rules for CloudTrail management events."""

import json
from typing import Any, Dict, Optional

from .rules import SecurityRule

ROOT_TECHNIQUE = "T1078.004"
MFA_TECHNIQUE = "T1078.004"
ACCESS_KEY_TECHNIQUE = "T1098.001"
IAM_POLICY_TECHNIQUE = "T1098"
CLOUDTRAIL_TAMPER_TECHNIQUE = "T1562.008"
GUARDDUTY_TAMPER_TECHNIQUE = "T1562.001"
BRUTE_FORCE_TECHNIQUE = "T1110.003"


def _alert(
    reason: str,
    details: str,
    technique: str,
    severity: str,
    tactic: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "is_alert": True,
        "alert_reason": reason,
        "details": details,
        "severity": severity,
        "mitre_technique": technique,
        "mitre_framework": "enterprise",
        "mitre_tactic": tactic,
    }


def _request_params(log: Dict[str, Any]) -> Dict[str, Any]:
    raw = log.get("request_parameters") or "{}"
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _actor(log: Dict[str, Any]) -> str:
    return log.get("user_arn") or log.get("user_name") or "unknown"


def _event_context(log: Dict[str, Any]) -> str:
    return (
        f"{log.get('event_name', 'unknown')} by {_actor(log)} "
        f"from {log.get('source_ip') or 'unknown'}"
    )


class RootAccountUsageRule(SecurityRule):
    """Any use of the account root identity is high-signal."""

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        user_type = str(log.get("user_type", "")).lower()
        user_arn = str(log.get("user_arn", ""))
        if user_type == "root" or user_arn.endswith(":root"):
            return _alert(
                "IDENTITY_ROOT_ACCOUNT_USAGE",
                f"Root account activity detected: {_event_context(log)}",
                ROOT_TECHNIQUE,
                "HIGH",
                "TA0001",
            )
        return None


class ConsoleLoginWithoutMfaRule(SecurityRule):
    """Console logins that explicitly report MFA was not used."""

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("event_name") != "ConsoleLogin":
            return None

        mfa_used = str(log.get("mfa_used", "")).strip().lower()
        if mfa_used not in {"no", "false", "0"}:
            # Missing MFA metadata is not proof of a violation; stay quiet.
            return None

        return _alert(
            "IDENTITY_CONSOLE_LOGIN_WITHOUT_MFA",
            f"Console login without MFA: {_event_context(log)}",
            MFA_TECHNIQUE,
            "HIGH",
            "TA0001",
        )


class AccessKeyCreatedRule(SecurityRule):
    """Creation of long-lived programmatic credentials."""

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("event_name") != "CreateAccessKey":
            return None

        params = _request_params(log)
        target = params.get("userName") or _actor(log)
        return _alert(
            "IDENTITY_ACCESS_KEY_CREATED",
            f"Access key created for {target} by {_actor(log)} from {log.get('source_ip') or 'unknown'}",
            ACCESS_KEY_TECHNIQUE,
            "HIGH",
            "TA0003",
        )


class IamPolicyModifiedRule(SecurityRule):
    """Privilege changes to IAM users, groups, roles or policies."""

    PRIVILEGE_EVENTS = {
        "AttachUserPolicy",
        "AttachGroupPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutGroupPolicy",
        "PutRolePolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
    }
    REMOVAL_EVENTS = {
        "DetachUserPolicy",
        "DetachGroupPolicy",
        "DetachRolePolicy",
        "DeleteUserPolicy",
        "DeleteGroupPolicy",
        "DeleteRolePolicy",
    }

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_name = log.get("event_name")
        if event_name not in self.PRIVILEGE_EVENTS and event_name not in self.REMOVAL_EVENTS:
            return None

        params = _request_params(log)
        target = (
            params.get("userName")
            or params.get("roleName")
            or params.get("groupName")
            or params.get("policyArn")
            or "unknown"
        )
        severity = "HIGH" if event_name in self.PRIVILEGE_EVENTS else "MEDIUM"
        return _alert(
            "IDENTITY_IAM_POLICY_MODIFIED",
            f"{event_name} on {target} by {_actor(log)} from {log.get('source_ip') or 'unknown'}",
            IAM_POLICY_TECHNIQUE,
            severity,
            "TA0003",
        )


class CloudTrailTamperingRule(SecurityRule):
    """Attempts to stop or modify audit logging."""

    TAMPER_EVENTS = {"StopLogging", "DeleteTrail", "UpdateTrail"}

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("event_name") not in self.TAMPER_EVENTS:
            return None
        return _alert(
            "IDENTITY_CLOUDTRAIL_TAMPERING",
            f"CloudTrail tampering attempt: {_event_context(log)}",
            CLOUDTRAIL_TAMPER_TECHNIQUE,
            "HIGH",
            "TA0005",
        )


class GuardDutyTamperingRule(SecurityRule):
    """Attempts to delete or disable the managed detector."""

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_name = log.get("event_name")
        if event_name == "DeleteDetector":
            return _alert(
                "IDENTITY_GUARDDUTY_TAMPERING",
                f"GuardDuty detector deleted: {_event_context(log)}",
                GUARDDUTY_TAMPER_TECHNIQUE,
                "HIGH",
                "TA0005",
            )

        if event_name == "UpdateDetector":
            params = _request_params(log)
            if params.get("enable") is False or str(params.get("status", "")).upper() == "DISABLED":
                return _alert(
                    "IDENTITY_GUARDDUTY_TAMPERING",
                    f"GuardDuty detector disabled: {_event_context(log)}",
                    GUARDDUTY_TAMPER_TECHNIQUE,
                    "HIGH",
                    "TA0005",
                )
        return None


class ConsoleLoginBruteForceRule(SecurityRule):
    """Repeated failed console logins from one source address."""

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 300,
        state_store: Optional[Any] = None,
    ):
        super().__init__(state_store)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._history: Dict[str, list] = {}

    @staticmethod
    def _is_failure(log: Dict[str, Any]) -> bool:
        if log.get("error_code"):
            return True
        return "failure" in str(log.get("response_elements", "")).lower()

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("event_name") != "ConsoleLogin" or not self._is_failure(log):
            return None

        source_ip = log.get("source_ip")
        if not source_ip:
            return None

        try:
            from log_parser_toolkit.parsers.utils import parse_timestamp

            timestamp_epoch = parse_timestamp(log.get("timestamp")).timestamp()
        except Exception:
            return None

        if self.state_store:
            hits = self.state_store.increment_bucket(
                key_prefix="identity_console_login",
                identifier=source_ip,
                timestamp_epoch=timestamp_epoch,
                window_seconds=self.window_seconds,
            )
        else:
            history = self._history.setdefault(source_ip, [])
            history.append(timestamp_epoch)
            while history and (timestamp_epoch - history[0]) > self.window_seconds:
                history.pop(0)
            hits = len(history)

        if hits >= self.threshold:
            return _alert(
                "IDENTITY_CONSOLE_LOGIN_BRUTE_FORCE",
                f"{hits} failed console logins from {source_ip} within {self.window_seconds}s",
                BRUTE_FORCE_TECHNIQUE,
                "MEDIUM",
                "TA0006",
            )
        return None


class IdentitySecurityAnalyzer:
    """Runs identity rules and consolidates their alerts for the handler."""

    def __init__(self, state_store: Optional[Any] = None):
        self.rules = [
            RootAccountUsageRule(state_store=state_store),
            ConsoleLoginWithoutMfaRule(state_store=state_store),
            AccessKeyCreatedRule(state_store=state_store),
            IamPolicyModifiedRule(state_store=state_store),
            CloudTrailTamperingRule(state_store=state_store),
            GuardDutyTamperingRule(state_store=state_store),
            ConsoleLoginBruteForceRule(state_store=state_store),
        ]

    def analyze(self, log: Dict[str, Any]) -> Dict[str, Any]:
        if log.get("error"):
            return log

        log["alerts"] = []
        for rule in self.rules:
            alert = rule.evaluate(log)
            if alert:
                log["alerts"].append(alert)

        if log["alerts"]:
            log["is_alert"] = True
            log["alert_reason"] = "; ".join(a.get("alert_reason", "Unknown") for a in log["alerts"])
            log["details"] = "; ".join(a.get("details", "") for a in log["alerts"])
            log["detection_domain"] = "identity"
        return log
