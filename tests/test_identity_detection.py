import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/parser_lambda')))

from log_parser_toolkit.analyzer.identity_rules import IdentitySecurityAnalyzer
from log_parser_toolkit.analyzer.state_store import InMemoryStateStore
from log_parser_toolkit.guardduty import normalize_guardduty_event, severity_from_score
from log_parser_toolkit.parsers.cloudtrail import CloudTrailParser

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(*parts):
    return os.path.join(FIXTURES, *parts)


def _parse_cloudtrail(*parts):
    parser = CloudTrailParser(_fixture(*parts))
    with parser as stream:
        return list(stream.parse())


class TestCloudTrailParser(unittest.TestCase):
    def test_normalizes_identity_fields(self):
        records = _parse_cloudtrail("cloudtrail", "sample_trail.json")

        self.assertEqual(len(records), 4)
        root_login = records[0]
        self.assertEqual(root_login["event_name"], "ConsoleLogin")
        self.assertEqual(root_login["user_type"], "Root")
        self.assertEqual(root_login["mfa_used"], "No")
        self.assertEqual(root_login["source_ip"], "203.0.113.5")
        self.assertEqual(root_login["account_id"], "000000000000")
        self.assertEqual(root_login["user_arn"], "arn:aws:iam::000000000000:root")

    def test_preserves_request_parameters_as_json(self):
        records = _parse_cloudtrail("cloudtrail", "sample_trail.json")
        access_key = records[1]
        self.assertEqual(json.loads(access_key["request_parameters"]), {"userName": "bob"})

    def test_invalid_json_yields_an_error_record(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            handle.write("{not-json")
            name = handle.name
        try:
            parser = CloudTrailParser(name)
            with parser as stream:
                records = list(stream.parse())
            self.assertEqual(len(records), 1)
            self.assertIn("error", records[0])
        finally:
            os.remove(name)


class TestIdentityRules(unittest.TestCase):
    def setUp(self):
        self.analyzer = IdentitySecurityAnalyzer(state_store=InMemoryStateStore())
        self.events = _parse_cloudtrail("cloudtrail", "sample_trail.json")

    def test_root_console_login_without_mfa_raises_two_alerts(self):
        result = self.analyzer.analyze(self.events[0])

        reasons = {alert["alert_reason"] for alert in result["alerts"]}
        self.assertEqual(
            reasons,
            {"IDENTITY_ROOT_ACCOUNT_USAGE", "IDENTITY_CONSOLE_LOGIN_WITHOUT_MFA"},
        )
        self.assertTrue(result["is_alert"])
        self.assertEqual(result["detection_domain"], "identity")
        self.assertTrue(all(alert["severity"] == "HIGH" for alert in result["alerts"]))
        self.assertTrue(all(alert["mitre_framework"] == "enterprise" for alert in result["alerts"]))

    def test_access_key_creation_is_detected(self):
        result = self.analyzer.analyze(self.events[1])

        self.assertEqual(len(result["alerts"]), 1)
        alert = result["alerts"][0]
        self.assertEqual(alert["alert_reason"], "IDENTITY_ACCESS_KEY_CREATED")
        self.assertEqual(alert["mitre_technique"], "T1098.001")
        self.assertIn("bob", alert["details"])

    def test_cloudtrail_tampering_is_detected(self):
        result = self.analyzer.analyze(self.events[2])

        self.assertEqual(result["alerts"][0]["alert_reason"], "IDENTITY_CLOUDTRAIL_TAMPERING")
        self.assertEqual(result["alerts"][0]["mitre_technique"], "T1562.008")

    def test_benign_event_has_no_alerts(self):
        result = self.analyzer.analyze(self.events[3])

        self.assertFalse(result.get("is_alert", False))
        self.assertEqual(result["alerts"], [])

    def test_iam_policy_change_is_detected(self):
        result = self.analyzer.analyze({
            "event_name": "AttachUserPolicy",
            "event_source": "iam.amazonaws.com",
            "user_arn": "arn:aws:iam::000000000000:user/alice",
            "source_ip": "198.51.100.7",
            "request_parameters": json.dumps({"userName": "bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
            "timestamp": "2026-10-24T12:05:00Z",
        })

        self.assertEqual(result["alerts"][0]["alert_reason"], "IDENTITY_IAM_POLICY_MODIFIED")
        self.assertEqual(result["alerts"][0]["severity"], "HIGH")

    def test_guardduty_disable_is_detected(self):
        result = self.analyzer.analyze({
            "event_name": "UpdateDetector",
            "event_source": "guardduty.amazonaws.com",
            "user_arn": "arn:aws:iam::000000000000:user/alice",
            "source_ip": "198.51.100.7",
            "request_parameters": json.dumps({"detectorId": "abc", "enable": False}),
            "timestamp": "2026-10-24T12:06:00Z",
        })

        self.assertEqual(result["alerts"][0]["alert_reason"], "IDENTITY_GUARDDUTY_TAMPERING")

    def test_console_failures_cross_threshold(self):
        failures = _parse_cloudtrail("cloudtrail", "console_failures.json")
        results = [self.analyzer.analyze(row) for row in failures]

        self.assertFalse(any(result.get("is_alert") for result in results[:4]))
        self.assertTrue(results[4]["is_alert"])
        self.assertEqual(results[4]["alerts"][0]["alert_reason"], "IDENTITY_CONSOLE_LOGIN_BRUTE_FORCE")

    def test_missing_mfa_metadata_does_not_alert(self):
        result = self.analyzer.analyze({
            "event_name": "ConsoleLogin",
            "user_type": "IAMUser",
            "user_arn": "arn:aws:iam::000000000000:user/alice",
            "source_ip": "198.51.100.7",
            "mfa_used": "",
            "timestamp": "2026-10-24T12:05:00Z",
        })

        self.assertEqual(result["alerts"], [])


class TestGuardDutyNormalizer(unittest.TestCase):
    def setUp(self):
        with open(_fixture("guardduty", "finding.json"), encoding="utf-8") as handle:
            self.event = json.load(handle)

    def test_normalizes_finding(self):
        row = normalize_guardduty_event(self.event)

        self.assertEqual(row["guardduty_type"], "CredentialAccess:IAMUser/AnomalousBehavior")
        self.assertEqual(row["alert_reason"], "GUARDDUTY_CREDENTIALACCESS_IAMUSER_ANOMALOUSBEHAVIOR")
        self.assertEqual(row["severity"], "HIGH")
        self.assertEqual(row["source_ip"], "203.0.113.99")
        self.assertEqual(row["host"], "alice")
        self.assertEqual(row["mitre_tactic"], "TA0006")
        self.assertEqual(row["mitre_framework"], "enterprise")
        self.assertEqual(row["detection_domain"], "identity")

    def test_severity_bands(self):
        self.assertEqual(severity_from_score(8.0), "HIGH")
        self.assertEqual(severity_from_score(5.5), "MEDIUM")
        self.assertEqual(severity_from_score(2.0), "LOW")
        self.assertEqual(severity_from_score("bad"), "LOW")


if __name__ == "__main__":
    unittest.main()
