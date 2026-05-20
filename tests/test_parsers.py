import unittest
import sys
import os
import tempfile

# Add the lambda source path so log_parser_toolkit can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/parser_lambda')))

from log_parser_toolkit.parsers.linux import LinuxSyslogParser
from log_parser_toolkit.parsers.json import JsonLinesParser

class TestParsers(unittest.TestCase):
    def test_linux_parser_rfc3164(self):
        # Create a temporary file with standard Linux syslog lines
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
            f.write("May 20 18:25:30 ot-gateway kernel: [12345.6789] test syslog message\n")
            temp_name = f.name
            
        try:
            parser = LinuxSyslogParser(temp_name)
            with parser as p:
                records = list(p.parse())
            
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec["hostname"], "ot-gateway")
            self.assertEqual(rec["process"], "kernel")
            self.assertEqual(rec["message"], "[12345.6789] test syslog message")
        finally:
            os.remove(temp_name)

    def test_json_lines_parser(self):
        # Create a temporary file with Suricata JSON alerts
        raw_json_line = '{"timestamp": "2026-05-20T19:27:26.798635+0000", "event_type": "alert", "src_ip": "172.24.0.10", "dest_ip": "172.21.0.10", "alert": {"signature": "Modbus Unauthorized FC", "category": "ICS"}}'
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
            f.write(raw_json_line + "\n")
            temp_name = f.name
            
        try:
            parser = JsonLinesParser(temp_name)
            with parser as p:
                records = list(p.parse())
                
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec["src_ip"], "172.24.0.10")
            self.assertEqual(rec["dest_ip"], "172.21.0.10")
            self.assertEqual(rec["event_type"], "alert")
            self.assertEqual(rec["alert"]["signature"], "Modbus Unauthorized FC")
        finally:
            os.remove(temp_name)

if __name__ == "__main__":
    unittest.main()
