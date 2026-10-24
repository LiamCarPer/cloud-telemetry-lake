import json
from typing import Any, Dict, Iterator, List, Optional

from .base import BaseParser


class CloudTrailParser(BaseParser):
    """
    Parses CloudTrail log files (a JSON object with a top-level Records array)
    and normalizes the identity-relevant fields.
    """

    FORMAT_NAME = "cloudtrail"

    def __init__(self, file_path: str, encoding: Optional[str] = None, **kwargs):
        super().__init__(file_path, encoding=encoding)

    def get_fields(self) -> List[str]:
        return [
            "timestamp",
            "event_name",
            "event_source",
            "event_type",
            "aws_region",
            "account_id",
            "user_arn",
            "user_name",
            "user_type",
            "source_ip",
            "user_agent",
            "mfa_used",
            "error_code",
            "request_parameters",
            "response_elements",
            "raw_line",
            "error",
        ]

    def parse(self) -> Iterator[Dict[str, Any]]:
        if not self._file:
            raise RuntimeError("Parser must be used as a context manager (using 'with').")

        content = self._file.read()
        try:
            payload = json.loads(content)
        except Exception as exc:
            yield {"raw_line": content[:200], "error": f"CloudTrail JSON parse error: {exc}"}
            return

        if isinstance(payload, dict):
            records = payload.get("Records", [])
        elif isinstance(payload, list):
            records = payload
        else:
            records = []

        if not isinstance(records, list):
            yield {"raw_line": content[:200], "error": "CloudTrail payload has no Records array"}
            return

        for event in records:
            if not isinstance(event, dict):
                yield {"raw_line": str(event)[:200], "error": "CloudTrail record is not an object"}
                continue
            yield self._normalize(event)

    @staticmethod
    def _normalize(event: Dict[str, Any]) -> Dict[str, Any]:
        identity = event.get("userIdentity") or {}
        additional = event.get("additionalEventData") or {}
        request = event.get("requestParameters") or {}
        response = event.get("responseElements") or {}

        mfa_used = additional.get("MFAUsed")
        if mfa_used is None:
            mfa_used = response.get("MFAUsed", "")

        return {
            "timestamp": event.get("eventTime", ""),
            "event_name": event.get("eventName", ""),
            "event_source": event.get("eventSource", ""),
            "event_type": event.get("eventType", ""),
            "aws_region": event.get("awsRegion", ""),
            "account_id": identity.get("accountId") or event.get("recipientAccountId", ""),
            "user_arn": identity.get("arn") or identity.get("principalId", ""),
            "user_name": identity.get("userName", ""),
            "user_type": identity.get("type", ""),
            "source_ip": event.get("sourceIPAddress", ""),
            "user_agent": event.get("userAgent", ""),
            "mfa_used": mfa_used if mfa_used is not None else "",
            "error_code": event.get("errorCode", ""),
            "request_parameters": json.dumps(request, sort_keys=True, default=str) if request else "",
            "response_elements": json.dumps(response, sort_keys=True, default=str) if response else "",
            "raw_line": json.dumps(event, sort_keys=True, default=str),
        }
