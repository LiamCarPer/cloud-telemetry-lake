from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseWriter(ABC):
    """
    Abstract base class for all log writers.
    """
    def __init__(self, output_path: str, fields: List[str], encoding: str = 'utf-8'):
        self.output_path = output_path
        self.fields = fields
        self.encoding = encoding

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @abstractmethod
    def write_row(self, row: Dict[str, Any]):
        """Writes a single row to the output."""
        pass

    @abstractmethod
    def close(self):
        """Closes any open file handles."""
        pass
