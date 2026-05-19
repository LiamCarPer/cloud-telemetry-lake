import re
from typing import Iterator, Dict, Any, List, Optional
from .base import BaseParser
from .utils import normalize_timestamp

class WebLogParser(BaseParser):
    """
    Parses Apache/Nginx combined log format files.
    """
    FORMAT_NAME = "web"
    
    DEFAULT_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<bytes>\S+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"$'
    )

    def __init__(self, file_path: str, encoding: Optional[str] = None, custom_pattern: Optional[str] = None):
        super().__init__(file_path, encoding=encoding)
        self.pattern = re.compile(custom_pattern) if custom_pattern else self.DEFAULT_PATTERN

    def get_fields(self) -> List[str]:
        return ["ip", "ident", "user", "timestamp", "request", "status", "bytes", "referer", "user_agent", "raw_line", "error"]

    def parse(self) -> Iterator[Dict[str, Any]]:
        fields = self.get_fields()
        if not self._file:
            raise RuntimeError("Parser must be used as a context manager (using 'with').")
            
        for line in self._file:
                match = self.pattern.match(line.strip())
                res = {f: None for f in fields}
                if match:
                    res.update(match.groupdict())
                    # Temporal Normalization
                    res['timestamp'] = normalize_timestamp(res['timestamp'], ["%d/%b/%Y:%H:%M:%S %z"])
                else:
                    res.update({"raw_line": line.strip(), "error": "unmatched"})
                yield res
