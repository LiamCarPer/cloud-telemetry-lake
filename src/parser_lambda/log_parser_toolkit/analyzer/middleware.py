from typing import Dict, Any, List, Optional
import logging
try:
    import geoip2.database
except ImportError:
    geoip2 = None

from .rules import (
    SecurityRule, SSHBruteForceRule, PrivilegeEscalationRule, 
    WebScanningRule, UserAgentAnomalyRule, WindowsFailedLogonRule,
    ModbusAnomalyRule, S7commAnomalyRule
)
from .threat_intel import ThreatIntelCache
from .state_store import StateStore

logger = logging.getLogger(__name__)

class StatefulSecurityAnalyzer:
    """
    A middleware layer that analyzes logs for threats and enriches them with intelligence.
    Sits between parsing and output. Supports distributed state.
    """
    def __init__(self, state_store: Optional[StateStore] = None, abuseipdb_key: Optional[str] = None, geoip_db_path: Optional[str] = None):
        self.state_store = state_store
        
        # Initialize rules with the distributed/local state store
        self.rules: List[SecurityRule] = [
            SSHBruteForceRule(state_store=state_store),
            PrivilegeEscalationRule(state_store=state_store),
            WebScanningRule(state_store=state_store),
            UserAgentAnomalyRule(state_store=state_store),
            WindowsFailedLogonRule(state_store=state_store),
            ModbusAnomalyRule(state_store=state_store),
            S7commAnomalyRule(state_store=state_store)
        ]
        
        # Initialize threat intel cache
        self.intel_cache = ThreatIntelCache(abuseipdb_key)
        
        # Initialize GeoIP reader
        self.geoip_reader = None
        if geoip_db_path and geoip2:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")

    def analyze(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single log record.
        Returns the enriched record (modifies it in place).
        """
        if log.get("error"):
            # Don't analyze logs that failed parsing
            return log

        # Initialize alerts list
        log["alerts"] = []

        # Check for pre-existing alerts (e.g. from ot-sensor)
        if "alert_type" in log:
            log["alerts"].append({
                "is_alert": True,
                "alert_reason": log.get("alert_type"),
                "details": log.get("description") or log.get("details") or f"Alert triggered by sensor: {log.get('alert_type')}"
            })

        # Check for firewall drops in iptables logs
        if "rule_tag" in log and "DROP" in str(log.get("rule_tag")):
            log["alerts"].append({
                "is_alert": True,
                "alert_reason": "Firewall Packet Drop",
                "details": f"Packet dropped by firewall: {log.get('src_ip')} -> {log.get('dst_ip')} (In: {log.get('in_interface')}, Out: {log.get('out_interface')})"
            })

        # 1. Evaluate detection rules
        for rule in self.rules:
            alert = rule.evaluate(log)
            if alert:
                log["alerts"].append(alert)
        
        # 2. Enrich with Threat Intelligence & GeoIP
        ip = log.get('ip')
        if ip:
            # Threat Intel
            score = self.intel_cache.get_threat_score(ip)
            if score is not None:
                log['threat_score'] = score
                if score >= 80:
                    log["alerts"].append({
                        "is_alert": True,
                        "alert_reason": "Known Malicious IP",
                        "details": f"IP {ip} has high AbuseIPDB score: {score}"
                    })
            
            # GeoIP Enrichment
            if self.geoip_reader:
                try:
                    response = self.geoip_reader.city(ip)
                    log['country'] = response.country.name
                    log['city'] = response.city.name
                    
                    try:
                        asn_response = self.geoip_reader.asn(ip)
                        log['asn'] = asn_response.autonomous_system_number
                        log['isp'] = asn_response.autonomous_system_organization
                    except:
                        pass
                except Exception:
                    # Ignore lookup failures for internal/unmapped IPs
                    pass

        # 3. Consolidate alerts for flat output formats (CSV/SQLite)
        if log["alerts"]:
            log["is_alert"] = True
            log["alert_reason"] = "; ".join([a.get("alert_reason", "Unknown") for a in log["alerts"]])
            log["details"] = "; ".join([a.get("details", "") for a in log["alerts"]])
        
        return log

    def close(self):
        if self.geoip_reader:
            self.geoip_reader.close()
