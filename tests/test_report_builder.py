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

if __name__ == "__main__":
    unittest.main()
