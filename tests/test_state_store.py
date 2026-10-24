import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/parser_lambda')))

from log_parser_toolkit.analyzer.state_store import DynamoDBStateStore


class TestDynamoDBStateStore(unittest.TestCase):
    def setUp(self):
        self.table = MagicMock()
        self.resource = MagicMock()
        self.resource.Table.return_value = self.table
        self.resource.batch_get_item.return_value = {
            "Responses": {"ot_detection_state": [{"hit_count": 5}]}
        }
        self.resource_patcher = patch("boto3.resource", return_value=self.resource)
        self.resource_patcher.start()
        self.addCleanup(self.resource_patcher.stop)
        self.store = DynamoDBStateStore(
            table_name="ot_detection_state",
            endpoint_url="http://localhost:4566",
        )

    def test_increment_aliases_dynamodb_reserved_keywords(self):
        total = self.store.increment_bucket(
            key_prefix="identity_console_login",
            identifier="203.0.113.99",
            timestamp_epoch=1000.0,
            window_seconds=300,
        )

        self.assertEqual(total, 5)
        kwargs = self.table.update_item.call_args.kwargs
        self.assertIn("#ttl", kwargs["ExpressionAttributeNames"])
        self.assertIn("#hits", kwargs["ExpressionAttributeNames"])
        self.assertNotIn("ttl", kwargs["UpdateExpression"].split())
        self.assertIn("#ttl", kwargs["UpdateExpression"])
        self.assertEqual(kwargs["ExpressionAttributeValues"][":inc"], 1)


class TestInMemoryStoreStillWorks(unittest.TestCase):
    def test_in_memory_path_unaffected(self):
        from log_parser_toolkit.analyzer.state_store import InMemoryStateStore

        store = InMemoryStateStore()
        self.assertEqual(store.increment_bucket("k", "id", 100.0), 1)
        self.assertEqual(store.increment_bucket("k", "id", 105.0), 2)


if __name__ == "__main__":
    unittest.main()
