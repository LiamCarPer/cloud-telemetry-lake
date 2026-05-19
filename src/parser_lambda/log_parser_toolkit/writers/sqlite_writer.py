import sqlite3
from typing import Dict, Any, List
from .base import BaseWriter

class SQLiteWriter(BaseWriter):
    def __init__(self, output_path: str, fields: List[str], encoding: str = 'utf-8'):
        super().__init__(output_path, fields, encoding)
        self.conn = sqlite3.connect(self.output_path)
        self.cursor = self.conn.cursor()
        
        # Sanitize field names for SQL
        self.sql_fields = [f.replace("-", "_").replace(" ", "_") for f in self.fields]
        placeholders = ", ".join(["?" for _ in self.sql_fields])
        columns_def = ", ".join([f"{f} TEXT" for f in self.sql_fields])
        
        self.cursor.execute(f"DROP TABLE IF EXISTS logs")
        self.cursor.execute(f"CREATE TABLE logs ({columns_def})")
        
        self.insert_sql = f"INSERT INTO logs ({', '.join(self.sql_fields)}) VALUES ({placeholders})"
        self.batch = []

    def write_row(self, row: Dict[str, Any]):
        values = [str(row.get(f, "")) for f in self.fields]
        self.batch.append(values)
        
        if len(self.batch) >= 1000:
            self.cursor.executemany(self.insert_sql, self.batch)
            self.batch = []

    def close(self):
        if hasattr(self, 'batch') and self.batch:
            self.cursor.executemany(self.insert_sql, self.batch)
            self.batch = []
        if hasattr(self, 'conn') and self.conn:
            self.conn.commit()
            self.conn.close()
            self.conn = None
