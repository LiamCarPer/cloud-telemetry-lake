from abc import ABC, abstractmethod
from typing import Iterator, Dict, Any, List, Optional
import os
import gzip
import sys

class BaseParser(ABC):
    """
    Abstract base class for all log parsers.
    """
    
    FORMAT_NAME = ""

    def __init__(self, file_path: str, encoding: Optional[str] = None):
        if file_path != "-" and not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")
        self.file_path = file_path
        self._file = None
        self.encoding = encoding if encoding else 'utf-8'

    def __enter__(self):
        if self.file_path == "-":
            self._file = sys.stdin
        elif self.file_path.endswith('.gz'):
            self._file = gzip.open(self.file_path, 'rt', encoding=self.encoding, errors='ignore')
        else:
            self._file = open(self.file_path, 'r', encoding=self.encoding, errors='ignore')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file and self.file_path != "-":
            self._file.close()

    @abstractmethod
    def get_fields(self) -> List[str]:
        """
        Returns the list of field names that this parser produces.
        """
        pass

    @abstractmethod
    def parse(self) -> Iterator[Dict[str, Any]]:
        """
        Parses the log file and yields dictionaries,
        where each dictionary represents a parsed log line.
        """
        pass
