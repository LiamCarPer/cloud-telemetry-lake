"""Regression guards for security-relevant Terraform configuration.

These are intentionally static assertions, not a substitute for IAM policy
validation in a real AWS account. They exist so a future edit cannot silently
reintroduce a wildcard, an unused destructive action, or a plaintext secret.
"""

import os
import re
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TERRAFORM_DIR = os.path.join(REPO_ROOT, "terraform")


def _read(name: str) -> str:
    with open(os.path.join(TERRAFORM_DIR, name), encoding="utf-8") as handle:
        return handle.read()


class TestIamInvariants(unittest.TestCase):
    def setUp(self):
        self.iam = _read("iam.tf")

    def test_no_unused_destructive_dynamodb_actions(self):
        self.assertNotIn('"dynamodb:Scan"', self.iam)
        self.assertNotIn('"dynamodb:DeleteItem"', self.iam)

    def test_log_permissions_are_scoped_to_function_log_groups(self):
        self.assertNotIn("arn:aws:logs:*:*:*", self.iam)
        self.assertIn("aws_cloudwatch_log_group.parser.arn", self.iam)
        self.assertIn("aws_cloudwatch_log_group.aggregator.arn", self.iam)

    def test_both_roles_have_permissions_boundary(self):
        boundary_references = self.iam.count(
            "permissions_boundary = aws_iam_policy.lambda_permissions_boundary.arn"
        )
        self.assertEqual(boundary_references, 2)

    def test_queue_policies_pin_source_account(self):
        for filename in ("sqs.tf", "sns.tf"):
            with self.subTest(file=filename):
                self.assertIn('"aws:SourceAccount"', _read(filename))


class TestSecretsInvariants(unittest.TestCase):
    def test_lambda_uses_secret_reference_not_plaintext_key(self):
        lambda_tf = _read("lambda.tf")
        self.assertIn("ABUSEIPDB_SECRET_ARN", lambda_tf)
        self.assertNotIn("ABUSEIPDB_API_KEY", lambda_tf)

    def test_secret_value_is_not_managed_by_terraform(self):
        secrets = _read("secrets.tf")
        self.assertNotIn("aws_secretsmanager_secret_version", secrets)
        self.assertNotIn("secret_string", secrets)

    def test_kms_key_rotation_enabled(self):
        self.assertRegex(_read("kms.tf"), r"enable_key_rotation\s*=\s*true")


class TestMonitoringInvariants(unittest.TestCase):
    def test_failure_paths_have_alarms(self):
        monitoring = _read("monitoring.tf")
        for alarm in ("parser_errors", "aggregator_errors", "ingest_dlq_depth", "ingest_queue_age"):
            with self.subTest(alarm=alarm):
                self.assertIn(f'aws_cloudwatch_metric_alarm" "{alarm}"', monitoring)


class TestIdentityPlaneInvariants(unittest.TestCase):
    def test_identity_role_has_permissions_boundary(self):
        identity = _read("identity.tf")
        self.assertIn(
            "permissions_boundary = aws_iam_policy.lambda_permissions_boundary.arn",
            identity,
        )

    def test_real_services_are_gated(self):
        variables = _read("variables.tf")
        identity = _read("identity.tf")
        self.assertRegex(variables, r'variable "enable_cloudtrail"[\s\S]*?default\s*=\s*false')
        self.assertRegex(variables, r'variable "enable_guardduty"[\s\S]*?default\s*=\s*false')
        self.assertRegex(identity, r'resource "aws_cloudtrail" "identity"[\s\S]*?count\s*=\s*var\.enable_cloudtrail')
        self.assertRegex(identity, r'resource "aws_guardduty_detector" "identity"[\s\S]*?count\s*=\s*var\.enable_guardduty')

    def test_identity_lambda_uses_shared_artifact_and_handler(self):
        identity = _read("identity.tf")
        self.assertIn('handler          = "identity_handler.lambda_handler"', identity)
        self.assertIn("aws_s3_object.lambda_zip_upload.key", identity)


if __name__ == "__main__":
    unittest.main()
