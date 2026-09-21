import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

# Add the lambda source path so log_parser_toolkit can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src/parser_lambda')))

from log_parser_toolkit.analyzer.middleware import StatefulSecurityAnalyzer
from log_parser_toolkit.analyzer.rules import (
    ModbusAnomalyRule,
    PrivilegeEscalationRule,
    S7commAnomalyRule,
    SSHBruteForceRule,
    UserAgentAnomalyRule,
    WebScanningRule,
    WindowsFailedLogonRule,
)
from log_parser_toolkit.analyzer.state_store import InMemoryStateStore

BASE_TIME = datetime(2026, 5, 20, 10, 0, 0, tzinfo=timezone.utc)


def _ts(seconds: int) -> str:
    """Fixed-date ISO timestamp so rolling-window maths are deterministic."""
    return (BASE_TIME + timedelta(seconds=seconds)).isoformat()


class TestSSHBruteForceRule(unittest.TestCase):
    def setUp(self):
        self.rule = SSHBruteForceRule(threshold=5, window_seconds=60, state_store=InMemoryStateStore())

    @staticmethod
    def _failed_login(seconds: int):
        return {
            "process": "sshd",
            "message": "Failed password for root from 10.0.0.9 port 2222 ssh2",
            "ip": "10.0.0.9",
            "timestamp": _ts(seconds),
        }

    def test_triggers_on_fifth_attempt_within_window(self):
        for attempt in range(4):
            self.assertIsNone(self.rule.evaluate(self._failed_login(attempt * 10)))

        alert = self.rule.evaluate(self._failed_login(40))

        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "SSH Brute Force")

    def test_old_attempts_expire_from_window(self):
        for attempt in range(4):
            self.assertIsNone(self.rule.evaluate(self._failed_login(attempt * 10)))

        # 4 attempts at 0/10/20/30s; the next one at 120s falls outside the
        # 60s window, so only one hit remains and no alert fires.
        self.assertIsNone(self.rule.evaluate(self._failed_login(120)))

    def test_ignores_non_sshd_events(self):
        log = {"process": "cron", "message": "Failed password in a cron log line", "ip": "10.0.0.9", "timestamp": _ts(0)}
        self.assertIsNone(self.rule.evaluate(log))


class TestPrivilegeEscalationRule(unittest.TestCase):
    def setUp(self):
        self.rule = PrivilegeEscalationRule()

    def test_detects_root_shell(self):
        alert = self.rule.evaluate({
            "process": "sudo",
            "message": "pam_unix(sudo:session): session opened for user root by USER=root",
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "Privilege Escalation")

    def test_ignores_routine_sudo(self):
        log = {"process": "sudo", "message": "USER=deploy ; COMMAND=/usr/bin/apt-get update"}
        self.assertIsNone(self.rule.evaluate(log))


class TestWebScanningRule(unittest.TestCase):
    def setUp(self):
        self.rule = WebScanningRule(threshold=10, window_seconds=60, state_store=InMemoryStateStore())

    @staticmethod
    def _request(status: int, seconds: int):
        return {"ip": "203.0.113.5", "status": status, "timestamp": _ts(seconds)}

    def test_triggers_on_error_spike(self):
        for request in range(9):
            self.assertIsNone(self.rule.evaluate(self._request(404, request * 5)))

        alert = self.rule.evaluate(self._request(404, 50))

        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "Web Directory Scanning")

    def test_successful_requests_do_not_count(self):
        for request in range(12):
            self.assertIsNone(self.rule.evaluate(self._request(200, request * 5)))


class TestUserAgentAnomalyRule(unittest.TestCase):
    def setUp(self):
        self.rule = UserAgentAnomalyRule()

    def test_flags_scanner_user_agent(self):
        alert = self.rule.evaluate({"status": 200, "request": "/", "user_agent": "sqlmap/1.7"})
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "Suspicious User-Agent")

    def test_flags_missing_user_agent(self):
        alert = self.rule.evaluate({"status": 200, "request": "/", "user_agent": "-"})
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "Missing User-Agent")

    def test_allows_browser_user_agent(self):
        log = {"status": 200, "request": "/", "user_agent": "Mozilla/5.0 (X11; Linux x86_64)"}
        self.assertIsNone(self.rule.evaluate(log))


class TestWindowsFailedLogonRule(unittest.TestCase):
    def setUp(self):
        self.rule = WindowsFailedLogonRule(threshold=5, window_seconds=60, state_store=InMemoryStateStore())

    @staticmethod
    def _failed_logon(seconds: int):
        return {
            "Id": "4625",
            "Message": "An account failed to log on. Account Name: jdoe",
            "TimeCreated": _ts(seconds),
        }

    def test_triggers_on_repeated_failures_for_account(self):
        for attempt in range(4):
            self.assertIsNone(self.rule.evaluate(self._failed_logon(attempt * 10)))

        alert = self.rule.evaluate(self._failed_logon(40))

        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "Windows Brute Force")
        self.assertIn("jdoe", alert["details"])

    def test_ignores_other_event_ids(self):
        log = {"Id": "4624", "Message": "Account Name: jdoe", "TimeCreated": _ts(0)}
        self.assertIsNone(self.rule.evaluate(log))


class TestModbusAnomalyRule(unittest.TestCase):
    def setUp(self):
        self.rule = ModbusAnomalyRule()

    def test_write_function_code_is_alerted(self):
        alert = self.rule.evaluate({"protocol": "modbus", "dst_port": 502, "modbus_func": 6, "src_ip": "172.24.0.10"})
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "OT Modbus Write Command")

    def test_read_function_code_is_not_alerted(self):
        log = {"protocol": "modbus", "dst_port": 502, "modbus_func": 3}
        self.assertIsNone(self.rule.evaluate(log))

    def test_exception_response_is_alerted(self):
        alert = self.rule.evaluate({"dst_port": 502, "function_code": 131})
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "OT Modbus Exception Response")

    def test_message_level_anomaly_is_alerted(self):
        alert = self.rule.evaluate({"dst_port": "502", "message": "Modbus illegal function request"})
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "OT Modbus Protocol Anomaly")

    def test_non_modbus_traffic_is_ignored(self):
        log = {"protocol": "http", "dst_port": 80, "message": "GET /index.html"}
        self.assertIsNone(self.rule.evaluate(log))


class TestS7commAnomalyRule(unittest.TestCase):
    def setUp(self):
        self.rule = S7commAnomalyRule()

    def test_cpu_stop_is_alerted(self):
        alert = self.rule.evaluate({
            "protocol": "s7comm",
            "dst_port": 102,
            "message": "S7comm CPU control: transition to stop",
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["alert_reason"], "OT Siemens S7comm PLC State Change")

    def test_read_operations_are_ignored(self):
        log = {"protocol": "s7comm", "dst_port": 102, "message": "S7comm read data block DB1"}
        self.assertIsNone(self.rule.evaluate(log))


class TestStatefulSecurityAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = StatefulSecurityAnalyzer(state_store=InMemoryStateStore())

    def test_gateway_sensor_alert_is_preserved(self):
        log = {
            "alert_type": "CROSS_ZONE_VIOLATION",
            "description": "IT host attempted to reach Level 1",
            "src_ip": "172.24.0.10",
        }
        result = self.analyzer.analyze(log)

        self.assertTrue(result["is_alert"])
        self.assertEqual(result["alert_reason"], "CROSS_ZONE_VIOLATION")

    def test_firewall_drop_is_alerted(self):
        log = {
            "rule_tag": "IPTABLES_DROP",
            "src_ip": "172.24.0.10",
            "dst_ip": "172.21.0.10",
            "in_interface": "eth2",
            "out_interface": "eth1",
        }
        result = self.analyzer.analyze(log)

        self.assertTrue(result["is_alert"])
        self.assertIn("Firewall Packet Drop", result["alert_reason"])

    def test_clean_record_stays_clean(self):
        result = self.analyzer.analyze({"process": "cron", "message": "job started", "timestamp": _ts(0)})

        self.assertFalse(result.get("is_alert", False))
        self.assertEqual(result["alerts"], [])


class TestInMemoryStateStore(unittest.TestCase):
    def test_counts_and_prunes_rolling_window(self):
        store = InMemoryStateStore()

        self.assertEqual(store.increment_bucket("ssh_brute_force", "10.0.0.9", 1000.0, window_seconds=60), 1)
        self.assertEqual(store.increment_bucket("ssh_brute_force", "10.0.0.9", 1005.0, window_seconds=60), 2)
        # 100s later the first two hits are outside the 60s window.
        self.assertEqual(store.increment_bucket("ssh_brute_force", "10.0.0.9", 1100.0, window_seconds=60), 1)

    def test_identifiers_are_isolated(self):
        store = InMemoryStateStore()

        store.increment_bucket("web_scanning", "198.51.100.1", 1000.0)
        self.assertEqual(store.increment_bucket("web_scanning", "198.51.100.2", 1000.0), 1)


if __name__ == "__main__":
    unittest.main()
