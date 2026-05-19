import urllib.request
import json
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class ThreatIntelCache:
    """
    Highly efficient local cache for IP threat intelligence.
    Checks a local dictionary first, then optionally queries AbuseIPDB.
    """
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache = {} # IP -> threat_score

    def get_threat_score(self, ip: str) -> Optional[int]:
        """
        Retrieves the threat score (0-100) for an IP address.
        """
        if not ip:
            return None
            
        if ip in self.cache:
            return self.cache[ip]
            
        if not self.api_key:
            # If no API key, we can't fetch new scores, but we can't return 0 either 
            # as that would be misleading. We return None.
            return None
            
        score = self._fetch_from_abuseipdb(ip)
        if score is not None:
            self.cache[ip] = score
        return score

    def _fetch_from_abuseipdb(self, ip: str) -> Optional[int]:
        """
        Queries the AbuseIPDB API for the confidence of abuse score.
        """
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        
        try:
            # Using urllib to avoid external dependencies like 'requests'
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                # Return the abuseConfidenceScore (0-100)
                return data.get('data', {}).get('abuseConfidenceScore')
        except Exception as e:
            # Log error but don't crash the pipeline
            logger.debug(f"Could not fetch threat intelligence for {ip}: {e}")
            return None
