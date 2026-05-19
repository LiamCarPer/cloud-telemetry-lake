import json
from typing import Dict, Any, List
from .base import BaseWriter

class JSONWriter(BaseWriter):
    def __init__(self, output_path: str, fields: List[str], encoding: str = 'utf-8'):
        super().__init__(output_path, fields, encoding)
        self.file = open(self.output_path, 'w', encoding=self.encoding)
        self.file.write('[\n')
        self.is_first = True

    def write_row(self, row: Dict[str, Any]):
        if not self.is_first:
            self.file.write(',\n')
        self.file.write('    ' + json.dumps(row))
        self.is_first = False

    def close(self):
        if hasattr(self, 'file') and self.file:
            self.file.write('\n]\n')
            self.file.close()
            self.file = None
