import os
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from collections import deque
import boto3

logger = logging.getLogger(__name__)

class StateStore(ABC):
    """
    Abstract base class defining state store operations for detection rules.
    """
    @abstractmethod
    def increment_bucket(self, key_prefix: str, identifier: str, timestamp_epoch: float, window_seconds: int = 60, bucket_width_seconds: int = 10) -> int:
        pass

class InMemoryStateStore(StateStore):
    """
    Local, in-memory state store fallback for local execution and testing.
    """
    def __init__(self):
        self._store = {} # Key -> deque of timestamps

    def increment_bucket(self, key_prefix: str, identifier: str, timestamp_epoch: float, window_seconds: int = 60, bucket_width_seconds: int = 10) -> int:
        full_key = f"{key_prefix}#{identifier}"
        if full_key not in self._store:
            self._store[full_key] = deque()
            
        history = self._store[full_key]
        history.append(timestamp_epoch)
        
        # Remove timestamps older than the window
        while history and (timestamp_epoch - history[0]) > window_seconds:
            history.popleft()
            
        return len(history)

class DynamoDBStateStore(StateStore):
    """
    Production-grade distributed state store utilizing Amazon DynamoDB.
    Supports atomic bucket-based rolling window counters and automatic TTL expiration.
    """
    def __init__(self, table_name: str = "ot_detection_state", endpoint_url: Optional[str] = None):
        self.table_name = table_name
        self.endpoint_url = endpoint_url or os.environ.get("AWS_ENDPOINT_URL")
        
        # Initialize boto3 DynamoDB resource
        if self.endpoint_url:
            self.dynamodb = boto3.resource(
                "dynamodb",
                endpoint_url=self.endpoint_url,
                aws_access_key_id="mock",
                aws_secret_access_key="mock",
                region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
            )
        else:
            self.dynamodb = boto3.resource("dynamodb")
            
        self.table = self.dynamodb.Table(self.table_name)

    def increment_bucket(self, key_prefix: str, identifier: str, timestamp_epoch: float, window_seconds: int = 60, bucket_width_seconds: int = 10) -> int:
        """
        Increments the counter for a specific time-window bucket and returns the total sum
        of all active buckets within the rolling window.
        """
        # Determine the current bucket start time
        current_bucket = int(timestamp_epoch / bucket_width_seconds) * bucket_width_seconds
        current_key = f"{key_prefix}#{identifier}#{current_bucket}"
        
        # Calculate TTL (current bucket timestamp + window_seconds + safety margin)
        ttl_value = int(current_bucket + window_seconds + 300) # 5-minute safety margin
        
        try:
            # Atomically increment the count for the current bucket
            self.table.update_item(
                Key={"state_key": current_key},
                UpdateExpression="ADD hit_count :inc SET ttl = :ttl",
                ExpressionAttributeValues={
                    ":inc": 1,
                    ":ttl": ttl_value
                }
            )
        except Exception as e:
            logger.error(f"Failed to increment state bucket in DynamoDB: {e}")
            
        # Retrieve all bucket counts within the rolling window
        start_bucket = int((timestamp_epoch - window_seconds) / bucket_width_seconds) * bucket_width_seconds
        active_buckets = list(range(start_bucket, current_bucket + bucket_width_seconds, bucket_width_seconds))
        
        keys_to_fetch = [{"state_key": f"{key_prefix}#{identifier}#{b}"} for b in active_buckets]
        
        total_hits = 0
        try:
            # Retrieve all bucket values using BatchGetItem
            if keys_to_fetch:
                response = self.dynamodb.batch_get_item(
                    RequestItems={
                        self.table_name: {
                            "Keys": keys_to_fetch,
                            "ConsistentRead": True
                        }
                    }
                )
                items = response.get("Responses", {}).get(self.table_name, [])
                for item in items:
                    total_hits += int(item.get("hit_count", 0))
        except Exception as e:
            logger.error(f"Failed to fetch active state buckets from DynamoDB: {e}")
            return 1
            
        return total_hits
