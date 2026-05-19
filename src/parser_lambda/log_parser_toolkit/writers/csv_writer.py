import csv
from typing import Dict, Any, List
from .base import BaseWriter

class CSVWriter(BaseWriter):
    def __init__(self, output_path: str, fields: List[str], encoding: str = 'utf-8'):
        super().__init__(output_path, fields, encoding)
        self.file = open(self.output_path, 'w', newline='', encoding=self.encoding)
        self.writer = csv.DictWriter(self.file, fieldnames=self.fields)
        self.writer.writeheader()

    def write_row(self, row: Dict[str, Any]):
        # Filter row to only include known fields to avoid extras_action errors
        filtered_row = {k: v for k, v in row.items() if k in self.fields}
        self.writer.writerow(filtered_row)

    def close(self):
        if hasattr(self, 'file') and self.file:
            self.file.close()
            self.file = None
