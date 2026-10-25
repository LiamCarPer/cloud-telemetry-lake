"""Kubernetes audit-log detection rules."""

import json
from typing import Any, Dict, Optional

from .rules import SecurityRule

EXEC_TECHNIQUE = "T1609"
ESCAPE_TECHNIQUE = "T1611"
RBAC_TECHNIQUE = "T1098"
# ATT&CK technique IDs, not credentials (bandit B105 false positive).
SECRET_TECHNIQUE = "T1552.007"  # nosec B105
TAMPER_TECHNIQUE = "T1562.001"

SENSITIVE_HOST_PATHS = ("/", "/etc", "/proc", "/var/run/docker.sock", "/root", "/var/lib/kubelet")


def _alert(
    reason: str,
    details: str,
    severity: str,
    technique: Optional[str] = None,
    tactic: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "is_alert": True,
        "alert_reason": reason,
        "details": details,
        "severity": severity,
        "mitre_technique": technique,
        "mitre_framework": "containers",
        "mitre_tactic": tactic,
    }


def _request(log: Dict[str, Any]) -> Dict[str, Any]:
    raw = log.get("request_object") or ""
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _pod_spec(request: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(request.get("spec"), dict):
        return request["spec"]
    template = request.get("spec", {}).get("template", {}) if isinstance(request.get("spec"), dict) else {}
    if isinstance(template, dict) and isinstance(template.get("spec"), dict):
        return template["spec"]
    return {}


def _is_risky_pod(spec: Dict[str, Any]) -> bool:
    if spec.get("hostPID") or spec.get("hostNetwork") or spec.get("hostIPC"):
        return True
    for container in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        security = (container or {}).get("securityContext") or {}
        if security.get("privileged") is True:
            return True
    return False


def _sensitive_host_path(spec: Dict[str, Any]) -> Optional[str]:
    for volume in spec.get("volumes") or []:
        host_path = (volume or {}).get("hostPath") or {}
        path = str(host_path.get("path", ""))
        if not path:
            continue
        if path == "/" or any(path == prefix or path.startswith(prefix + "/") for prefix in SENSITIVE_HOST_PATHS if prefix != "/"):
            return path
    return None


def _is_wildcard_binding(request: Dict[str, Any]) -> bool:
    role_ref = request.get("roleRef") or {}
    if role_ref.get("name") == "cluster-admin":
        return True
    for rule in request.get("rules") or []:
        if "*" in (rule.get("verbs") or []) or "*" in (rule.get("resources") or []):
            return True
    return False


def _actor(log: Dict[str, Any]) -> str:
    return log.get("username") or "unknown"


def _target(log: Dict[str, Any]) -> str:
    namespace = log.get("namespace") or "-"
    return f"{log.get('resource') or 'resource'}/{log.get('object_name') or '-'} in {namespace}"


class PodExecRule(SecurityRule):
    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if (
            log.get("verb") in ("create", "get")
            and log.get("resource") == "pods"
            and log.get("subresource") in ("exec", "attach")
        ):
            return _alert(
                "K8S_POD_EXEC",
                f"{log.get('subresource')} into {log.get('namespace')}/{log.get('object_name')} "
                f"by {_actor(log)} from {log.get('source_ip') or 'unknown'}",
                "HIGH",
                EXEC_TECHNIQUE,
                "TA0002",
            )
        return None


class PrivilegedPodRule(SecurityRule):
    RISKY_VERBS = {"create", "update", "patch"}
    WORKLOAD_RESOURCES = {"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("verb") not in self.RISKY_VERBS or log.get("resource") not in self.WORKLOAD_RESOURCES:
            return None
        if _is_risky_pod(_pod_spec(_request(log))):
            return _alert(
                "K8S_PRIVILEGED_POD",
                f"Risky pod spec (privileged/host namespace) created by {_actor(log)}: {_target(log)}",
                "HIGH",
                ESCAPE_TECHNIQUE,
                "TA0004",
            )
        return None


class SensitiveHostPathRule(SecurityRule):
    RISKY_VERBS = {"create", "update", "patch"}
    WORKLOAD_RESOURCES = {"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("verb") not in self.RISKY_VERBS or log.get("resource") not in self.WORKLOAD_RESOURCES:
            return None
        path = _sensitive_host_path(_pod_spec(_request(log)))
        if path:
            return _alert(
                "K8S_SENSITIVE_HOSTPATH",
                f"Sensitive hostPath {path} mounted by {_actor(log)}: {_target(log)}",
                "HIGH",
                ESCAPE_TECHNIQUE,
                "TA0004",
            )
        return None


class ClusterAdminBindingRule(SecurityRule):
    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("resource") not in ("rolebindings", "clusterrolebindings"):
            return None
        if log.get("verb") not in ("create", "update", "patch"):
            return None
        if _is_wildcard_binding(_request(log)):
            return _alert(
                "K8S_CLUSTER_ADMIN_BINDING",
                f"Cluster-admin/wildcard binding changed by {_actor(log)}: {_target(log)}",
                "HIGH",
                RBAC_TECHNIQUE,
                "TA0003",
            )
        return None


class SecretAccessRule(SecurityRule):
    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("resource") == "secrets" and log.get("verb") in ("get", "list", "watch"):
            return _alert(
                "K8S_SECRET_ACCESS",
                f"Secret {log.get('verb')} by {_actor(log)}: {_target(log)}",
                "MEDIUM",
                SECRET_TECHNIQUE,
                "TA0006",
            )
        if log.get("resource") == "serviceaccounts" and log.get("subresource") == "token":
            return _alert(
                "K8S_SERVICE_ACCOUNT_TOKEN",
                f"Service-account token requested by {_actor(log)}: {_target(log)}",
                "HIGH",
                SECRET_TECHNIQUE,
                "TA0006",
            )
        return None


class AnonymousAccessRule(SecurityRule):
    HEALTH_PATHS = ("/healthz", "/livez", "/readyz", "/version", "/openapi", "/metrics")
    DISCOVERY_ROOTS = ("/api", "/apis")

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        groups = str(log.get("user_groups", ""))
        is_anonymous = (
            log.get("username") in ("system:anonymous", "system:unauthenticated")
            or "system:unauthenticated" in groups
        )
        if not is_anonymous:
            return None
        request_uri = str(log.get("request_uri", ""))
        is_health = (
            request_uri in self.DISCOVERY_ROOTS
            or any(request_uri == path or request_uri.startswith(path + "/") for path in self.HEALTH_PATHS)
        )
        if request_uri and is_health:
            # kube-probe and discovery endpoints are expected anonymous traffic.
            return None
        try:
            code = int(log.get("response_code") or 0)
        except (TypeError, ValueError):
            code = 0
        if code and code >= 400:
            return None
        return _alert(
            "K8S_ANONYMOUS_ACCESS",
            f"Anonymous request succeeded: {log.get('verb')} {_target(log)} from {log.get('source_ip') or 'unknown'}",
            "HIGH",
            None,
            "TA0001",
        )


class RbacChangeRule(SecurityRule):
    RESOURCES = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
    SKIP_RESOURCES = {"mutatingwebhookconfigurations", "validatingwebhookconfigurations"}

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("resource") not in self.RESOURCES:
            return None
        if log.get("verb") not in ("create", "update", "patch", "delete", "deletecollection"):
            return None
        # Cluster-admin and webhook changes have dedicated, higher-severity rules.
        if _is_wildcard_binding(_request(log)):
            return None
        return _alert(
            "K8S_RBAC_CHANGE",
            f"RBAC change by {_actor(log)}: {log.get('verb')} {_target(log)}",
            "MEDIUM",
            RBAC_TECHNIQUE,
            "TA0003",
        )


class AdmissionWebhookTamperRule(SecurityRule):
    RESOURCES = {"mutatingwebhookconfigurations", "validatingwebhookconfigurations"}

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if log.get("resource") not in self.RESOURCES:
            return None
        if log.get("verb") not in ("create", "update", "patch", "delete", "deletecollection"):
            return None
        return _alert(
            "K8S_ADMISSION_WEBHOOK_TAMPER",
            f"Admission webhook configuration changed by {_actor(log)}: {log.get('verb')} {_target(log)}",
            "HIGH",
            TAMPER_TECHNIQUE,
            "TA0005",
        )


class KubernetesSecurityAnalyzer:
    """Runs Kubernetes audit rules and consolidates alerts."""

    def __init__(self):
        self.rules = [
            PodExecRule(),
            PrivilegedPodRule(),
            SensitiveHostPathRule(),
            ClusterAdminBindingRule(),
            SecretAccessRule(),
            AnonymousAccessRule(),
            RbacChangeRule(),
            AdmissionWebhookTamperRule(),
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
            log["detection_domain"] = "kubernetes"
        return log
