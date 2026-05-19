from typing import List
from .base import BaseWriter
from .json_writer import JSONWriter
from .csv_writer import CSVWriter
from .sqlite_writer import SQLiteWriter

def get_writer(output_type: str, output_path: str, fields: List[str]) -> BaseWriter:
    if output_type == "json":
        return JSONWriter(output_path, fields)
    elif output_type == "csv":
        return CSVWriter(output_path, fields)
    elif output_type == "db":
        return SQLiteWriter(output_path, fields)
    else:
        raise ValueError(f"Unsupported output type: {output_type}")
