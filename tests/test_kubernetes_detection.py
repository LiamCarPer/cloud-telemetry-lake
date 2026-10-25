import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/parser_lambda')))

from log_parser_toolkit.analyzer.kubernetes_rules import KubernetesSecurityAnalyzer
from log_parser_toolkit.falco import normalize_falco_event
from log_parser_toolkit.guardduty import normalize_guardduty_event
from log_parser_toolkit.parsers.falco import FalcoParser
from log_parser_toolkit.parsers.kubernetes_audit import KubernetesAuditParser

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _audit_events():
    parser = KubernetesAuditParser(os.path.join(FIXTURES, "kubernetes", "audit_events.json"))
    with parser as stream:
        return list(stream.parse())


class TestKubernetesAuditParser(unittest.TestCase):
    def test_parses_event_list(self):
        events = _audit_events()
        self.assertEqual(len(events), 8)

        exec_event = events[0]
        self.assertEqual(exec_event["verb"], "create")
        self.assertEqual(exec_event["resource"], "pods")
        self.assertEqual(exec_event["subresource"], "exec")
        self.assertEqual(exec_event["username"], "kubernetes-admin")
        self.assertEqual(exec_event["source_ip"], "172.18.0.1")
        self.assertEqual(exec_event["response_code"], "101")
        self.assertEqual(exec_event["request_received_timestamp"], "2026-10-25T10:00:00Z")

    def test_redacts_secret_request_and_response(self):
        secret_event = _audit_events()[4]
        self.assertEqual(secret_event["resource"], "secrets")
        self.assertEqual(secret_event["request_object"], "")
        self.assertNotIn("should-not-be-stored", secret_event["raw_line"])


class TestKubernetesRules(unittest.TestCase):
    def setUp(self):
        self.analyzer = KubernetesSecurityAnalyzer()
        self.events = _audit_events()

    def _reasons(self, index):
        result = self.analyzer.analyze(self.events[index])
        return [alert["alert_reason"] for alert in result["alerts"]]

    def test_exec_is_detected(self):
        self.assertEqual(self._reasons(0), ["K8S_POD_EXEC"])

    def test_exec_get_verb_is_detected(self):
        result = self.analyzer.analyze({
            "verb": "get",
            "resource": "pods",
            "subresource": "exec",
            "namespace": "demo",
            "object_name": "web",
            "username": "kubernetes-admin",
            "source_ip": "172.19.0.1",
            "response_code": "101",
            "timestamp": "2026-10-25T00:23:50Z",
        })
        self.assertEqual([alert["alert_reason"] for alert in result["alerts"]], ["K8S_POD_EXEC"])

    def test_privileged_pod_is_detected(self):
        self.assertIn("K8S_PRIVILEGED_POD", self._reasons(1))

    def test_sensitive_hostpath_is_detected(self):
        self.assertIn("K8S_SENSITIVE_HOSTPATH", self._reasons(2))

    def test_cluster_admin_binding_is_not_double_reported_as_rbac_change(self):
        reasons = self._reasons(3)
        self.assertEqual(reasons, ["K8S_CLUSTER_ADMIN_BINDING"])

    def test_secret_access_is_detected(self):
        self.assertEqual(self._reasons(4), ["K8S_SECRET_ACCESS"])

    def test_anonymous_access_is_detected(self):
        self.assertEqual(self._reasons(5), ["K8S_ANONYMOUS_ACCESS"])

    def test_anonymous_health_probe_is_ignored(self):
        result = self.analyzer.analyze({
            "username": "system:anonymous",
            "user_groups": '["system:unauthenticated"]',
            "request_uri": "/readyz",
            "verb": "get",
            "resource": "pods",
            "response_code": "200",
            "timestamp": "2026-10-25T10:05:00Z",
        })
        self.assertEqual(result["alerts"], [])

    def test_webhook_tamper_is_detected(self):
        self.assertEqual(self._reasons(6), ["K8S_ADMISSION_WEBHOOK_TAMPER"])

    def test_benign_event_has_no_alerts(self):
        result = self.analyzer.analyze(self.events[7])
        self.assertEqual(result["alerts"], [])

    def test_alerts_use_containers_framework_and_domain(self):
        result = self.analyzer.analyze(self.events[0])
        self.assertEqual(result["detection_domain"], "kubernetes")
        self.assertEqual(result["alerts"][0]["mitre_framework"], "containers")
        self.assertEqual(result["alerts"][0]["mitre_technique"], "T1609")


class TestFalcoNormalizer(unittest.TestCase):
    def test_shell_rule_maps_to_high_severity(self):
        parser = FalcoParser(os.path.join(FIXTURES, "kubernetes", "falco_shell.json"))
        with parser as stream:
            rows = list(stream.parse())

        normalized = normalize_falco_event({
            "time": rows[0]["timestamp"],
            "rule": rows[0]["rule"],
            "priority": rows[0]["priority"],
            "source": rows[0]["source"],
            "hostname": rows[0]["hostname"],
            "output": rows[0]["message"],
            "output_fields": {
                "k8s.ns.name": rows[0]["namespace"],
                "k8s.pod.name": rows[0]["pod"],
                "container.name": rows[0]["container"],
                "proc.name": rows[0]["process"],
                "proc.cmdline": rows[0]["command"],
                "fd.name": rows[0]["file"],
                "user.name": rows[0]["user"],
                "fd.sip": rows[0]["source_ip"],
            },
        })

        self.assertEqual(normalized["alert_reason"], "FALCO_TERMINAL_SHELL_IN_CONTAINER")
        self.assertEqual(normalized["severity"], "HIGH")
        self.assertEqual(normalized["mitre_technique"], "T1609")
        self.assertEqual(normalized["mitre_framework"], "containers")
        self.assertEqual(normalized["namespace"], "default")
        self.assertEqual(normalized["host"], "web-0")
        self.assertEqual(normalized["source_ip"], "10.244.0.7")

    def test_unknown_rule_uses_priority_mapping(self):
        normalized = normalize_falco_event({
            "time": "2026-10-25T10:00:00Z",
            "rule": "Unexpected outbound connection",
            "priority": "Warning",
            "output": "connection to unknown host",
            "output_fields": {"k8s.pod.name": "web-0"},
        })

        self.assertEqual(normalized["severity"], "MEDIUM")
        self.assertIsNone(normalized["mitre_technique"])
        self.assertEqual(normalized["detection_domain"], "kubernetes")


class TestGuardDutyEksFinding(unittest.TestCase):
    def test_eks_finding_normalizes(self):
        with open(os.path.join(FIXTURES, "guardduty", "eks_finding.json"), encoding="utf-8") as handle:
            event = json.load(handle)

        row = normalize_guardduty_event(event)

        self.assertEqual(row["guardduty_type"], "Execution:Kubernetes/ExecInKubelet")
        self.assertEqual(row["severity"], "HIGH")
        self.assertEqual(row["mitre_tactic"], "TA0002")
        self.assertEqual(row["host"], "web-0")
        self.assertEqual(row["namespace"], "default")
        self.assertEqual(row["source_ip"], "203.0.113.50")
        self.assertEqual(row["detection_domain"], "kubernetes")
        self.assertEqual(row["mitre_framework"], "containers")


if __name__ == "__main__":
    unittest.main()
