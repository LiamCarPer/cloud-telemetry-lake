import json
from typing import Any, Dict, Iterator, List, Optional

from .base import BaseParser


def _find_first(obj: Any, key: str) -> Optional[str]:
    """Depth-first search for the first string value under `key`."""
    if isinstance(obj, dict):
        if key in obj and isinstance(obj[key], str):
            return obj[key]
        for value in obj.values():
            found = _find_first(value, key)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_first(item, key)
            if found:
                return found
    return None


class KubernetesAuditParser(BaseParser):
    """Parses Kubernetes audit EventList / Event JSON."""

    FORMAT_NAME = "kubernetes_audit"

    def __init__(self, file_path: str, encoding: Optional[str] = None, **kwargs):
        super().__init__(file_path, encoding=encoding)

    def get_fields(self) -> List[str]:
        return [
            "timestamp",
            "request_received_timestamp",
            "audit_id",
            "stage",
            "verb",
            "username",
            "user_groups",
            "namespace",
            "resource",
            "subresource",
            "object_name",
            "api_group",
            "request_uri",
            "source_ip",
            "user_agent",
            "response_code",
            "request_object",
            "container_image",
            "workload",
            "raw_line",
            "error",
        ]

    def parse(self) -> Iterator[Dict[str, Any]]:
        if not self._file:
            raise RuntimeError("Parser must be used as a context manager (using 'with').")

        content = self._file.read().strip()
        records: List[Any] = []
        try:
            payload = json.loads(content)
            if isinstance(payload, dict) and payload.get("kind") == "EventList":
                records = payload.get("items", [])
            elif isinstance(payload, dict) and payload.get("kind") == "Event":
                records = [payload]
            elif isinstance(payload, list):
                records = payload
            else:
                records = [payload]
        except Exception:
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except Exception as exc:
                    yield {"raw_line": line[:200], "error": f"Kubernetes audit parse error: {exc}"}

        if not isinstance(records, list):
            yield {"raw_line": content[:200], "error": "Kubernetes audit payload is not an event list"}
            return

        for event in records:
            if not isinstance(event, dict):
                yield {"raw_line": str(event)[:200], "error": "audit record is not an object"}
                continue
            yield self._normalize(event)

    @staticmethod
    def _normalize(event: Dict[str, Any]) -> Dict[str, Any]:
        user = event.get("user") or {}
        ref = event.get("objectRef") or {}
        response_status = event.get("responseStatus") or {}
        source_ips = event.get("sourceIPs") or []

        resource = ref.get("resource", "")
        # Never persist secret contents in the lake.
        request_object = {} if resource == "secrets" else (event.get("requestObject") or {})
        request_json = json.dumps(request_object, sort_keys=True, default=str) if request_object else ""

        sanitized = event
        if resource == "secrets":
            sanitized = {k: v for k, v in event.items() if k not in ("requestObject", "responseObject")}

        return {
            "timestamp": event.get("stageTimestamp") or event.get("requestReceivedTimestamp", ""),
            "request_received_timestamp": event.get("requestReceivedTimestamp", ""),
            "audit_id": event.get("auditID", ""),
            "stage": event.get("stage", ""),
            "verb": event.get("verb", ""),
            "username": user.get("username", ""),
            "user_groups": json.dumps(user.get("groups", []), default=str),
            "namespace": ref.get("namespace", ""),
            "resource": resource,
            "subresource": ref.get("subresource", ""),
            "object_name": ref.get("name", ""),
            "api_group": ref.get("apiVersion", ""),
            "request_uri": event.get("requestURI", ""),
            "source_ip": source_ips[0] if source_ips else "",
            "user_agent": event.get("userAgent", ""),
            "response_code": str(response_status.get("code", "")),
            "request_object": request_json,
            "container_image": _find_first(request_object, "image") or "",
            "workload": ref.get("name", ""),
            "raw_line": json.dumps(sanitized, sort_keys=True, default=str),
        }
