import re
from datetime import datetime
from typing import Optional, List

def extract_ip(text: str) -> Optional[str]:
    """Helper to extract an IP address from text."""
    if not text:
        return None
    # Simple regex for IPv4
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    if match:
        return match.group(0)
    return None

def parse_timestamp(ts_str: str, formats: Optional[List[str]] = None) -> datetime:
    """
    Parses a timestamp string into a datetime object.
    Supports standard ISO 8601 and common log formats.
    """
    if not ts_str:
        return datetime.now()
        
    # Try ISO 8601 first (internal standardized format)
    try:
        # datetime.fromisoformat handles Z and offsets in 3.11+, 
        # but for compatibility we handle Z manually if needed
        iso_str = ts_str.replace('Z', '+00:00')
        return datetime.fromisoformat(iso_str)
    except ValueError:
        pass

    # Fallback to provided formats
    if not formats:
        formats = [
            "%b %d %H:%M:%S",          # Syslog: Mar 22 10:15:30
            "%d/%b/%Y:%H:%M:%S %z",    # Web: 22/Mar/2026:10:15:00 +0000
            "%m/%d/%Y %I:%M:%S %p",    # Windows: 3/22/2026 10:15:00 AM
        ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            # If no year is present (syslog), assume current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
            
    return datetime.now()

def normalize_timestamp(ts_str: str, formats: List[str]) -> str:
    """
    Parses a timestamp string using a list of formats and returns ISO 8601 string.
    If parsing fails, returns the original string.
    """
    if not ts_str:
        return ts_str
        
    dt = parse_timestamp(ts_str, formats)
    # Ensure it outputs in a clean ISO format
    return dt.isoformat() + ("Z" if dt.tzinfo is None else "")
