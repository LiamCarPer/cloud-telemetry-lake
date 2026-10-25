import json
from typing import Any, Dict, Iterator, List, Optional

from .base import BaseParser


class FalcoParser(BaseParser):
    """Parses Falco JSON output (JSON lines or a JSON array)."""

    FORMAT_NAME = "falco"

    def __init__(self, file_path: str, encoding: Optional[str] = None, **kwargs):
        super().__init__(file_path, encoding=encoding)

    def get_fields(self) -> List[str]:
        return [
            "timestamp",
            "rule",
            "priority",
            "source",
            "hostname",
            "namespace",
            "pod",
            "container",
            "process",
            "command",
            "file",
            "user",
            "source_ip",
            "message",
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
            records = payload if isinstance(payload, list) else [payload]
        except Exception:
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except Exception as exc:
                    yield {"raw_line": line[:200], "error": f"Falco parse error: {exc}"}

        for event in records:
            if not isinstance(event, dict):
                yield {"raw_line": str(event)[:200], "error": "Falco record is not an object"}
                continue
            yield self._normalize(event)

    @staticmethod
    def _normalize(event: Dict[str, Any]) -> Dict[str, Any]:
        fields = event.get("output_fields") or {}
        if not isinstance(fields, dict):
            fields = {}

        def field(*names: str) -> str:
            for name in names:
                value = fields.get(name)
                if value not in (None, ""):
                    return str(value)
            return ""

        return {
            "timestamp": event.get("time", ""),
            "rule": event.get("rule", ""),
            "priority": event.get("priority", ""),
            "source": event.get("source", ""),
            "hostname": event.get("hostname", ""),
            "namespace": field("k8s.ns.name", "ka.target.namespace"),
            "pod": field("k8s.pod.name", "ka.target.name"),
            "container": field("container.name", "container.id"),
            "process": field("proc.name"),
            "command": field("proc.cmdline"),
            "file": field("fd.name"),
            "user": field("user.name"),
            "source_ip": field("fd.sip", "evt.addr", "k8s.pod.ip"),
            "message": event.get("output", ""),
            "raw_line": json.dumps(event, sort_keys=True, default=str),
        }
