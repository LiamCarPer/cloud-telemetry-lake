import re
from typing import Iterator, Dict, Any, List, Optional
from .base import BaseParser
from .utils import normalize_timestamp

class LinuxSyslogParser(BaseParser):
    """
    Parses standard Linux syslog files.
    """
    FORMAT_NAME = "linux"
    
    DEFAULT_PATTERN = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>[a-zA-Z0-9_-]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)$"
    )
    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def __init__(self, file_path: str, encoding: Optional[str] = None, custom_pattern: Optional[str] = None):
        super().__init__(file_path, encoding=encoding)
        self.pattern = re.compile(custom_pattern) if custom_pattern else self.DEFAULT_PATTERN

    def get_fields(self) -> List[str]:
        return ["timestamp", "hostname", "process", "pid", "message", "ip", "raw_line", "error"]

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
                    res['timestamp'] = normalize_timestamp(res['timestamp'], ["%b %d %H:%M:%S"])
                    # Enrichment: extract IP from message if possible (e.g. for sshd)
                    ip_match = self.IP_REGEX.search(res['message'])
                    if ip_match:
                        res['ip'] = ip_match.group(0)
                else:
                    res.update({"raw_line": line.strip(), "error": "unmatched"})
                yield res
