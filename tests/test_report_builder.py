import unittest
import sys
import os

# Ensure the root src folder is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.aggregator_lambda.report_builder import build_report

class TestReportBuilder(unittest.TestCase):
    def test_build_report_basic(self):
        detections = [
            {
                "incident_correlator": "UNAUTHORIZED_MODBUS_WRITE#ot-gateway",
                "timestamp": "2026-05-20T19:27:26.798635Z",
                "severity": "MEDIUM",
                "host": "ot-gateway",
                "src_ip": "172.24.0.10",
                "alert_reason": "UNAUTHORIZED_MODBUS_WRITE",
                "details": "Modbus FC 6 write attempt to coil 100",
                "original_key": "raw/source=sensor/date=2026-05-20/test.json"
            }
        ]
        
        report = build_report(detections)
        self.assertEqual(report["severity"], "MEDIUM")
        self.assertEqual(report["detection_count"], 1)
        self.assertIn("T0831", report["mitre_techniques"])
        self.assertEqual(report["affected_assets"]["hosts"], ["ot-gateway"])
        self.assertEqual(report["affected_assets"]["source_ips"], ["172.24.0.10"])
        self.assertTrue(len(report["recommended_actions"]) > 0)
        self.assertEqual(report["timeline"][0]["incident_correlator"], "UNAUTHORIZED_MODBUS_WRITE#ot-gateway")

    def test_build_report_severity_escalation(self):
        detections = [
            {"alert_reason": "UNAUTHORIZED_MODBUS_WRITE", "severity": "MEDIUM", "host": "plc1", "src_ip": "172.21.0.10"},
            {"alert_reason": "CROSS_ZONE_VIOLATION", "severity": "HIGH", "host": "gateway", "src_ip": "172.24.0.10"},
            {"alert_reason": "OT_BRUTE_FORCE_SCAN", "severity": "LOW", "host": "plc2", "src_ip": "172.21.0.11"}
        ]
        report = build_report(detections)
        self.assertEqual(report["severity"], "HIGH")
        self.assertEqual(report["detection_count"], 3)
        self.assertIn("T0831", report["mitre_techniques"])
        self.assertIn("T0886", report["mitre_techniques"])
        self.assertIn("T0846", report["mitre_techniques"])
        self.assertCountEqual(report["affected_assets"]["hosts"], ["gateway", "plc1", "plc2"])
        self.assertCountEqual(report["affected_assets"]["source_ips"], ["172.21.0.10", "172.21.0.11", "172.24.0.10"])

    # ------------------------------------------------------------------
    # Deterministic windowing / idempotency
    # ------------------------------------------------------------------

    @staticmethod
    def _detection(correlator, timestamp, severity="MEDIUM"):
        return {
            "incident_correlator": correlator,
            "timestamp": f"{timestamp}#abcdef1234567890",
            "event_timestamp": timestamp,
            "severity": severity,
            "host": "ot-gateway",
            "src_ip": "172.24.0.10",
            "alert_reason": "UNAUTHORIZED_MODBUS_WRITE",
        }

    def test_incident_id_is_deterministic(self):
        detections = [
            self._detection("UNAUTHORIZED_MODBUS_WRITE#172.24.0.10", "2026-05-20T19:27:26+00:00"),
            self._detection("CROSS_ZONE_VIOLATION#172.24.0.10", "2026-05-20T19:27:30+00:00", severity="HIGH"),
        ]

        first = build_report(list(detections))
        second = build_report(list(detections))

        self.assertEqual(first["incident_id"], second["incident_id"])
        self.assertEqual(
            first["window_start"],
            "2026-05-20T19:25:00+00:00",
        )
        self.assertEqual(
            first["window_end"],
            "2026-05-20T19:30:00+00:00",
        )

    def test_incident_id_is_order_independent(self):
        detections = [
            self._detection("UNAUTHORIZED_MODBUS_WRITE#172.24.0.10", "2026-05-20T19:27:26+00:00"),
            self._detection("CROSS_ZONE_VIOLATION#172.24.0.10", "2026-05-20T19:27:30+00:00", severity="HIGH"),
        ]

        forward = build_report(list(detections))
        reverse = build_report(list(reversed(detections)))

        self.assertEqual(forward["incident_id"], reverse["incident_id"])

    def test_window_separates_incidents(self):
        early = [self._detection("UNAUTHORIZED_MODBUS_WRITE#172.24.0.10", "2026-05-20T19:27:26+00:00")]
        late = [self._detection("UNAUTHORIZED_MODBUS_WRITE#172.24.0.10", "2026-05-20T19:31:01+00:00")]

        early_report = build_report(early)
        late_report = build_report(late)

        self.assertNotEqual(early_report["incident_id"], late_report["incident_id"])
        self.assertEqual(early_report["window_start"], "2026-05-20T19:25:00+00:00")
        self.assertEqual(late_report["window_start"], "2026-05-20T19:30:00+00:00")

    def test_window_end_covers_latest_detection(self):
        detections = [
            self._detection("UNAUTHORIZED_MODBUS_WRITE#172.24.0.10", "2026-05-20T19:27:26+00:00"),
            self._detection("CROSS_ZONE_VIOLATION#172.24.0.10", "2026-05-20T19:32:10+00:00", severity="HIGH"),
        ]

        report = build_report(detections)

        self.assertEqual(report["window_start"], "2026-05-20T19:25:00+00:00")
        self.assertEqual(report["window_end"], "2026-05-20T19:32:10+00:00")

    def test_custom_window_seconds(self):
        detections = [
            self._detection("UNAUTHORIZED_MODBUS_WRITE#172.24.0.10", "2026-05-20T19:27:26+00:00")
        ]

        wide = build_report(list(detections), window_seconds=300)
        narrow = build_report(list(detections), window_seconds=60)

        self.assertNotEqual(wide["incident_id"], narrow["incident_id"])
        self.assertEqual(narrow["window_start"], "2026-05-20T19:27:00+00:00")

    def test_detections_without_timestamps_still_idempotent(self):
        detections = [
            {"incident_correlator": "SSH Brute Force#10.0.0.1", "alert_reason": "SSH Brute Force"},
        ]

        first = build_report(list(detections))
        second = build_report(list(detections))

        self.assertEqual(first["incident_id"], second["incident_id"])
        self.assertIsNone(first["window_start"])
        self.assertIsNone(first["window_end"])

    def test_parser_rule_reasons_map_to_ics_techniques(self):
        report = build_report([
            {
                "alert_reason": "OT Modbus Write Command",
                "severity": "MEDIUM",
                "host": "ot-gateway",
                "src_ip": "172.24.0.10",
            },
            {
                "alert_reason": "OT Siemens S7comm PLC State Change",
                "severity": "HIGH",
                "host": "ot-gateway",
                "src_ip": "172.24.0.10",
            },
        ])

        self.assertIn("T0831", report["mitre_techniques"])
        self.assertIn("T0813", report["mitre_techniques"])
        self.assertEqual(report["severity"], "HIGH")

    def test_identity_and_ot_detections_are_grouped_by_framework(self):
        detections = [
            {
                "incident_correlator": "IDENTITY_ROOT_ACCOUNT_USAGE#203.0.113.5",
                "timestamp": "2026-10-24T12:00:00Z#aaaa",
                "event_timestamp": "2026-10-24T12:00:00Z",
                "severity": "HIGH",
                "host": "root",
                "src_ip": "203.0.113.5",
                "alert_reason": "IDENTITY_ROOT_ACCOUNT_USAGE",
                "detection_domain": "identity",
                "mitre_technique": "T1078.004",
                "mitre_framework": "enterprise",
                "mitre_tactic": "TA0001",
            },
            {
                "incident_correlator": "UNAUTHORIZED_MODBUS_WRITE#172.24.0.10",
                "timestamp": "2026-10-24T12:02:00Z#bbbb",
                "event_timestamp": "2026-10-24T12:02:00Z",
                "severity": "MEDIUM",
                "host": "ot-gateway",
                "src_ip": "172.24.0.10",
                "alert_reason": "UNAUTHORIZED_MODBUS_WRITE",
                "detection_domain": "ot",
            },
        ]

        report = build_report(detections)

        self.assertEqual(report["mitre_techniques_by_framework"], {
            "ics": ["T0831"],
            "enterprise": ["T1078.004"],
            "containers": [],
        })
        self.assertEqual(report["mitre_techniques"], ["T0831", "T1078.004"])
        self.assertEqual(report["mitre_tactics"], ["TA0001"])
        self.assertEqual(report["detection_domains"], ["identity", "ot"])
        self.assertEqual(report["identity_detection_count"], 1)
        self.assertEqual(report["ot_detection_count"], 1)
        self.assertTrue(any("root credentials" in action.lower() for action in report["recommended_actions"]))

    def test_guardduty_findings_get_generic_actions(self):
        report = build_report([
            {
                "alert_reason": "GUARDDUTY_CREDENTIALACCESS_IAMUSER_ANOMALOUSBEHAVIOR",
                "severity": "HIGH",
                "host": "alice",
                "src_ip": "203.0.113.99",
                "detection_domain": "identity",
                "guardduty_type": "CredentialAccess:IAMUser/AnomalousBehavior",
            }
        ])

        self.assertTrue(any("Triage the GuardDuty finding" in action for action in report["recommended_actions"]))
        self.assertEqual(report["detection_domains"], ["identity"])

    def test_kubernetes_containers_framework_and_counts(self):
        detections = [
            {
                "incident_correlator": "K8S_POD_EXEC#172.18.0.1",
                "timestamp": "2026-10-25T10:00:01Z#aaaa",
                "event_timestamp": "2026-10-25T10:00:01Z",
                "severity": "HIGH",
                "host": "web-0",
                "src_ip": "172.18.0.1",
                "alert_reason": "K8S_POD_EXEC",
                "detection_domain": "kubernetes",
                "mitre_technique": "T1609",
                "mitre_framework": "containers",
                "mitre_tactic": "TA0002",
            },
            {
                "incident_correlator": "UNAUTHORIZED_MODBUS_WRITE#172.24.0.10",
                "timestamp": "2026-10-25T10:02:00Z#bbbb",
                "event_timestamp": "2026-10-25T10:02:00Z",
                "severity": "MEDIUM",
                "host": "ot-gateway",
                "src_ip": "172.24.0.10",
                "alert_reason": "UNAUTHORIZED_MODBUS_WRITE",
                "detection_domain": "ot",
            },
        ]

        report = build_report(detections)

        self.assertEqual(report["mitre_techniques_by_framework"]["containers"], ["T1609"])
        self.assertEqual(report["mitre_techniques_by_framework"]["ics"], ["T0831"])
        self.assertEqual(report["detection_domains"], ["kubernetes", "ot"])
        self.assertEqual(report["kubernetes_detection_count"], 1)
        self.assertEqual(report["ot_detection_count"], 1)
        self.assertTrue(any("exec" in action.lower() for action in report["recommended_actions"]))

    def test_falco_findings_get_runtime_actions(self):
        report = build_report([
            {
                "alert_reason": "FALCO_TERMINAL_SHELL_IN_CONTAINER",
                "severity": "HIGH",
                "host": "web-0",
                "src_ip": "10.244.0.7",
                "detection_domain": "kubernetes",
                "mitre_technique": "T1609",
                "mitre_framework": "containers",
                "falco_rule": "Terminal shell in container",
            }
        ])

        self.assertTrue(any("Triage the Falco event" in action for action in report["recommended_actions"]))
        self.assertEqual(report["kubernetes_detection_count"], 1)

if __name__ == "__main__":
    unittest.main()
