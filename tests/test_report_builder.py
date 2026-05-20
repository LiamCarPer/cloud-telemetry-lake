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

if __name__ == "__main__":
    unittest.main()
