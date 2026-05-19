import csv
from typing import Iterator, Dict, Any, List, Optional
from .base import BaseParser
from .utils import normalize_timestamp

class WindowsLogParser(BaseParser):
    """
    Parses Windows Event Logs that have been exported to CSV format.
    """
    FORMAT_NAME = "windows"
    REQUIRED_COLUMNS = {"TimeCreated", "Id", "LevelDisplayName", "ProviderName", "Message"}

    def __init__(self, file_path: str, encoding: Optional[str] = None, **kwargs):
        # kwargs to consume custom_pattern if passed by factory
        super().__init__(file_path, encoding=encoding)
        if not encoding and file_path != "-":
            self.encoding = 'utf-8-sig'
        self._cached_fields: Optional[List[str]] = None

    def get_fields(self) -> List[str]:
        if self._cached_fields:
            return self._cached_fields

        if self.file_path == "-":
            # Fallback for stdin where we can't easily peek without consuming
            return list(self.REQUIRED_COLUMNS) + ["raw_line", "error"]

        # If file is already open (context managed), use it
        if self._file and not self._file.closed:
            pos = self._file.tell()
            self._file.seek(0)
            reader = csv.reader(self._file)
            header = next(reader, [])
            self._file.seek(pos)
        else:
            # Not open, open once to read header
            with open(self.file_path, 'r', encoding=self.encoding, errors='ignore') as f:
                reader = csv.reader(f)
                header = next(reader, [])
            
        header_set = set(header)
        if not self.REQUIRED_COLUMNS.issubset(header_set):
            missing = self.REQUIRED_COLUMNS - header_set
            raise ValueError(f"Invalid Windows Event Log CSV schema. Missing columns: {missing}")
            
        self._cached_fields = header + ["raw_line", "error"]
        return self._cached_fields

    def parse(self) -> Iterator[Dict[str, Any]]:
        if not self._file:
            raise RuntimeError("Parser must be used as a context manager (using 'with').")
            
        reader = csv.DictReader(self._file)
        
        # Populate cache if it's empty (e.g. parse called before get_fields)
        if not self._cached_fields:
            self._cached_fields = (reader.fieldnames or []) + ["raw_line", "error"]

        for row in reader:
                # Normalization for Windows Time: 3/22/2026 10:15:00 AM
                if "TimeCreated" in row:
                    row["TimeCreated"] = normalize_timestamp(row["TimeCreated"], ["%m/%d/%Y %I:%M:%S %p"])
                yield row
