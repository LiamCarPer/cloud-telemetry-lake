import re
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from collections import deque
from datetime import datetime
from log_parser_toolkit.parsers.utils import extract_ip, parse_timestamp

class SecurityRule(ABC):
    """
    Abstract base class for all detection rules.
    """
    def __init__(self, state_store: Optional[Any] = None):
        self.state_store = state_store

    @abstractmethod
    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluates a log record and returns alert details if it matches, else None.
        """
        pass

class SSHBruteForceRule(SecurityRule):
    """
    Rule 1 (Velocity/Threshold): 5 failed logins from the same IP within 60 seconds.
    """
    def __init__(self, threshold: int = 5, window_seconds: int = 60, state_store: Optional[Any] = None):
        super().__init__(state_store)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.ip_history = {} # IP -> deque of timestamps (Fallback)

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        process = log.get('process')
        message = log.get('message', '')
        
        if process == 'sshd' and 'Failed password' in message:
            ip = log.get('ip') or extract_ip(message)
            if not ip:
                return None
            
            timestamp = parse_timestamp(log.get('timestamp'))
            timestamp_epoch = timestamp.timestamp()
            
            if self.state_store:
                hits = self.state_store.increment_bucket(
                    key_prefix="ssh_brute_force",
                    identifier=ip,
                    timestamp_epoch=timestamp_epoch,
                    window_seconds=self.window_seconds
                )
            else:
                if ip not in self.ip_history:
                    self.ip_history[ip] = deque()
                history = self.ip_history[ip]
                history.append(timestamp_epoch)
                while history and (timestamp_epoch - history[0]) > self.window_seconds:
                    history.popleft()
                hits = len(history)
            
            if hits >= self.threshold:
                return {
                    "is_alert": True,
                    "alert_reason": "SSH Brute Force",
                    "details": f"Detected {hits} failed logins from {ip} within {self.window_seconds}s"
                }
        return None

class PrivilegeEscalationRule(SecurityRule):
    """
    Rule 2 (Keyword Match): Sudo usage to root or spawning /bin/bash.
    """
    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        process = log.get('process')
        message = log.get('message', '')
        
        if process == 'sudo':
            if 'USER=root' in message or '/bin/bash' in message:
                return {
                    "is_alert": True,
                    "alert_reason": "Privilege Escalation",
                    "details": f"Sudo privilege escalation detected: {message}"
                }
        return None

class WebScanningRule(SecurityRule):
    """
    Rule 3 (Spike Detection): High volume of 404/5xx errors from an IP.
    """
    def __init__(self, threshold: int = 10, window_seconds: int = 60, state_store: Optional[Any] = None):
        super().__init__(state_store)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.ip_errors = {} # IP -> deque of timestamps (Fallback)

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ip = log.get('ip')
        status = log.get('status')
        
        if ip and status:
            try:
                status_int = int(status)
            except ValueError:
                return None
                
            if status_int >= 400:
                timestamp = parse_timestamp(log.get('timestamp'))
                timestamp_epoch = timestamp.timestamp()
                
                if self.state_store:
                    hits = self.state_store.increment_bucket(
                        key_prefix="web_scanning",
                        identifier=ip,
                        timestamp_epoch=timestamp_epoch,
                        window_seconds=self.window_seconds
                    )
                else:
                    if ip not in self.ip_errors:
                        self.ip_errors[ip] = deque()
                    errors = self.ip_errors[ip]
                    errors.append(timestamp_epoch)
                    while errors and (timestamp_epoch - errors[0]) > self.window_seconds:
                        errors.popleft()
                    hits = len(errors)
                
                if hits >= self.threshold:
                    return {
                        "is_alert": True,
                        "alert_reason": "Web Directory Scanning",
                        "details": f"Detected {hits} error responses (4xx/5xx) from {ip} within {self.window_seconds}s"
                    }
        return None

class UserAgentAnomalyRule(SecurityRule):
    """
    Rule 4 (Anomaly Detection): Flagging suspicious or weaponized user agents.
    """
    SUSPICIOUS_UA = {
        'sqlmap', 'nmap', 'nikto', 'dirbuster', 'gobuster', 
        'python-requests', 'curl', 'zgrab', 'masscan'
    }

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if 'status' not in log and 'request' not in log:
            return None

        ua = log.get('user_agent', '')
        if not ua or ua == '-':
            return {
                "is_alert": True,
                "alert_reason": "Missing User-Agent",
                "details": "Request sent with missing or empty User-Agent string."
            }
        
        ua_lower = ua.lower()
        for suspect in self.SUSPICIOUS_UA:
            if suspect in ua_lower:
                return {
                    "is_alert": True,
                    "alert_reason": "Suspicious User-Agent",
                    "details": f"Detected potential automated tool/scanner: {suspect}"
                }
        return None

class WindowsFailedLogonRule(SecurityRule):
    """
    Rule 5 (Velocity): 5 failed Windows logons from the same IP/Account within 60 seconds.
    Detects Event ID 4625 (Audit Failure).
    """
    def __init__(self, threshold: int = 5, window_seconds: int = 60, state_store: Optional[Any] = None):
        super().__init__(state_store)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.history = {} # Key -> deque of timestamps (Fallback)

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_id = str(log.get('Id') or log.get('EventID') or '')
        
        if event_id == '4625':
            msg = log.get('Message', '')
            target = "unknown"
            match = re.search(r"Account Name:\s+(\S+)", msg)
            if match:
                target = match.group(1)
            
            timestamp_str = log.get('TimeCreated') or log.get('timestamp')
            if not timestamp_str:
                return None
            
            timestamp = parse_timestamp(timestamp_str)
            timestamp_epoch = timestamp.timestamp()
            
            if self.state_store:
                hits = self.state_store.increment_bucket(
                    key_prefix="windows_brute_force",
                    identifier=target,
                    timestamp_epoch=timestamp_epoch,
                    window_seconds=self.window_seconds
                )
            else:
                if target not in self.history:
                    self.history[target] = deque()
                hist = self.history[target]
                hist.append(timestamp_epoch)
                while hist and (timestamp_epoch - hist[0]) > self.window_seconds:
                    hist.popleft()
                hits = len(hist)
            
            if hits >= self.threshold:
                return {
                    "is_alert": True,
                    "alert_reason": "Windows Brute Force",
                    "details": f"Detected {hits} failed logins for account '{target}' within {self.window_seconds}s"
                }
        return None

class ModbusAnomalyRule(SecurityRule):
    """
    Rule 6 (OT Protocol): Detects Modbus TCP anomalies (e.g., illegal function codes, unauthorized writes).
    Applies to telemetry originating from OT zone firewalls or protocol-aware logs on port 502.
    """
    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        proto = str(log.get("protocol", "")).lower()
        dst_port = str(log.get("dst_port", ""))
        src_port = str(log.get("src_port", ""))
        message = str(log.get("message", ""))
        
        is_modbus = (proto == "modbus" or dst_port == "502" or src_port == "502" or "modbus" in message.lower())
        if not is_modbus:
            return None
            
        function_code = log.get("modbus_func") or log.get("function_code")
        
        # Parse function code from message string if not explicitly defined
        if not function_code and message:
            match = re.search(r"(?:func|function)\s*(\d+)", message, re.IGNORECASE)
            if match:
                function_code = int(match.group(1))
                
        if function_code:
            try:
                func_val = int(function_code)
                # Control operations: 5 (Write Single Coil), 6 (Write Single Register), 15/16 (Write Multiple)
                if func_val in [5, 6, 15, 16]:
                    return {
                        "is_alert": True,
                        "alert_reason": "OT Modbus Write Command",
                        "details": f"Unauthorized Modbus write command (Function Code: {func_val}) from source: {log.get('ip') or log.get('src_ip', 'unknown')}"
                    }
                # Modbus Exception responses are function code + 128
                elif func_val >= 128:
                    return {
                        "is_alert": True,
                        "alert_reason": "OT Modbus Exception Response",
                        "details": f"Modbus Exception Response detected (Function Code: {func_val}). Potential device fault or scanning."
                    }
            except ValueError:
                pass
                
        if "illegal" in message.lower() or "exception" in message.lower():
            return {
                "is_alert": True,
                "alert_reason": "OT Modbus Protocol Anomaly",
                "details": f"Suspicious Modbus payload anomaly: {message}"
            }
            
        return None

class S7commAnomalyRule(SecurityRule):
    """
    Rule 7 (OT Protocol): Detects unauthorized Siemens S7comm CPU Control commands
    (e.g., PLC STOP, PLC START commands) which can disrupt industrial operations.
    """
    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        message = str(log.get("message", "")).lower()
        proto = str(log.get("protocol", "")).lower()
        dst_port = str(log.get("dst_port", ""))
        
        is_s7 = (proto == "s7comm" or dst_port == "102" or "s7comm" in message)
        if not is_s7:
            return None
            
        if "stop" in message or "cpu control" in message or "transition to stop" in message:
            return {
                "is_alert": True,
                "alert_reason": "OT Siemens S7comm PLC State Change",
                "details": f"Siemens S7comm CPU STOP command detected from {log.get('ip') or log.get('src_ip', 'unknown')}. Risk of process shutdown."
            }
            
        return None
