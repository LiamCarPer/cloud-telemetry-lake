"""Shared detection identifiers and record preparation helpers."""

import hashlib
import json
from typing import Any, Dict, List


def generate_event_id(original_key: str, timestamp: str, alert_reason: str, index: int) -> str:
    """Deterministic 16-character event fingerprint used in the DynamoDB sort key."""
    hasher = hashlib.sha256()
    raw_payload = f"{original_key}:{timestamp}:{alert_reason}:{index}"
    hasher.update(raw_payload.encode("utf-8"))
    return hasher.hexdigest()[:16]


def normalize_for_parquet(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten nested values so Parquet/Athena get scalar columns."""
    for row in rows:
        for key, value in list(row.items()):
            if isinstance(value, (dict, list)):
                row[key] = json.dumps(value, sort_keys=True, default=str)
    return rows
