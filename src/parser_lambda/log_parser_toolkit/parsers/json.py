import json
from typing import Iterator, Dict, Any, List, Optional
from .base import BaseParser

class JsonLinesParser(BaseParser):
    """
    Parses JSON Lines (.jsonl) or JSON array files.
    """
    FORMAT_NAME = "json"

    def __init__(self, file_path: str, encoding: Optional[str] = None, **kwargs):
        super().__init__(file_path, encoding=encoding)

    def get_fields(self) -> List[str]:
        # We return a standard set of fields, but JSON records can contain dynamic fields.
        return ["timestamp", "source", "host", "message", "raw_line", "error"]

    def parse(self) -> Iterator[Dict[str, Any]]:
        if not self._file:
            raise RuntimeError("Parser must be used as a context manager (using 'with').")
        
        # Read a small chunk to check if it's a JSON array
        content = self._file.read()
        self._file.seek(0)
        
        stripped = content.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            try:
                records = json.loads(stripped)
                for rec in records:
                    if isinstance(rec, dict):
                        yield rec
                    else:
                        yield {"raw_line": str(rec), "error": "not a dictionary"}
            except Exception as e:
                yield {"raw_line": stripped[:200], "error": f"JSON array parse error: {e}"}
        else:
            self._file.seek(0)
            for line in self._file:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    rec = json.loads(line_str)
                    if isinstance(rec, dict):
                        yield rec
                    else:
                        yield {"raw_line": line_str, "error": "not a dictionary"}
                except Exception as e:
                    yield {"raw_line": line_str, "error": f"JSON line parse error: {e}"}
