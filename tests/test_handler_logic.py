import unittest
import sys
import os
import json

# Add the lambda source path so handler can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/parser_lambda')))

# Mock boto3 and DynamoDB initialization to prevent connections during import
# Since the handler imports DynamoDBStateStore and other modules, let's mock the table initialization
import boto3
from unittest.mock import MagicMock, patch

# Mock DynamoDBTable before importing handler
original_resource = boto3.resource
def mock_resource(service, *args, **kwargs):
    if service == "dynamodb":
        mock_db = MagicMock()
        mock_db.Table.return_value = MagicMock()
        return mock_db
    return original_resource(service, *args, **kwargs)

boto3.resource = mock_resource

import handler

class TestHandlerLogic(unittest.TestCase):
    def test_get_severity_registry(self):
        self.assertEqual(handler.get_severity("SSH Brute Force"), "HIGH")
        self.assertEqual(handler.get_severity("UNAUTHORIZED_MODBUS_WRITE"), "MEDIUM")
        self.assertEqual(handler.get_severity("Privilege Escalation"), "MEDIUM")
        self.assertEqual(handler.get_severity("CROSS_ZONE_VIOLATION"), "HIGH")
        self.assertEqual(handler.get_severity("Some Unknown Anomaly"), "LOW")

    def test_extract_partition_metadata_hive(self):
        # Test hive partition structure
        key = "parsed/source=iptables/date=2026-05-20/file.parquet"
        source, date_str = handler.extract_partition_metadata(key)
        self.assertEqual(source, "iptables")
        self.assertEqual(date_str, "2026-05-20")

    def test_extract_partition_metadata_flat(self):
        # Test flat structure with folder names
        key = "malcolm/alerts.json"
        source, date_str = handler.extract_partition_metadata(key)
        self.assertEqual(source, "malcolm")
        # Check that it extracted a valid date format YYYY-MM-DD
        self.assertEqual(len(date_str.split('-')), 3)

        # Test folder name in path
        key = "some_directory/sensor/log_file.txt"
        source, date_str = handler.extract_partition_metadata(key)
        self.assertEqual(source, "sensor")

    def test_generate_event_id_determinism(self):
        key = "source=iptables/date=2026-05-20/file.parquet"
        ts = "2026-05-20T18:25:30Z"
        reason = "CROSS_ZONE_VIOLATION"
        
        id1 = handler.generate_event_id(key, ts, reason, 0)
        id2 = handler.generate_event_id(key, ts, reason, 0)
        id3 = handler.generate_event_id(key, ts, reason, 1) # different index
        
        self.assertEqual(id1, id2)
        self.assertNotEqual(id1, id3)
        self.assertEqual(len(id1), 16)

@patch.dict(os.environ, {"STAGED_BUCKET": "ot-telemetry-staged-test", "DLQ_BUCKET": "ot-telemetry-dlq-test"})
class TestHandlerBatchFailures(unittest.TestCase):
    """SQS partial batch response behaviour (ReportBatchItemFailures)."""

    def _sqs_event(self, body, message_id):
        return {"Records": [{"messageId": message_id, "body": body}]}

    def test_invalid_json_body_is_reported_as_failure(self):
        result = handler.lambda_handler(self._sqs_event("{not-json", "msg-invalid"), None)
        self.assertEqual(result["batchItemFailures"], [{"itemIdentifier": "msg-invalid"}])

    def test_message_without_s3_records_is_acknowledged(self):
        result = handler.lambda_handler(
            self._sqs_event(json.dumps({"Records": []}), "msg-empty"), None
        )
        self.assertEqual(result["batchItemFailures"], [])

    def test_missing_bucket_or_key_is_reported_as_failure(self):
        body = json.dumps({"Records": [{"s3": {"bucket": {"name": "raw"}, "object": {}}}]})
        result = handler.lambda_handler(self._sqs_event(body, "msg-malformed"), None)
        self.assertEqual(result["batchItemFailures"], [{"itemIdentifier": "msg-malformed"}])

    def test_download_failure_is_reported_as_failure(self):
        body = json.dumps({
            "Records": [{
                "s3": {
                    "bucket": {"name": "raw"},
                    "object": {"key": "source=syslog/date=2026-05-20/events.json"},
                }
            }]
        })
        with patch.object(handler.s3_client, "download_file", side_effect=RuntimeError("connection reset")):
            result = handler.lambda_handler(self._sqs_event(body, "msg-download"), None)
        self.assertEqual(result["batchItemFailures"], [{"itemIdentifier": "msg-download"}])

    def test_parseable_file_is_acknowledged(self):
        def fake_download(bucket, key, path):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("")

        body = json.dumps({
            "Records": [{
                "s3": {
                    "bucket": {"name": "raw"},
                    "object": {"key": "source=syslog/date=2026-05-20/empty.log"},
                }
            }]
        })
        with patch.object(handler.s3_client, "download_file", side_effect=fake_download):
            result = handler.lambda_handler(self._sqs_event(body, "msg-ok"), None)
        self.assertEqual(result["batchItemFailures"], [])


if __name__ == "__main__":
    unittest.main()
