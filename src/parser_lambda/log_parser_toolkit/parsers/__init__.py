from typing import Optional
from .base import BaseParser
from .linux import LinuxSyslogParser
from .web import WebLogParser
from .windows import WindowsLogParser
from .json import JsonLinesParser

def get_available_parsers():
    """
    Returns a dictionary mapping FORMAT_NAME to the parser class.
    """
    parsers = {}
    for cls in BaseParser.__subclasses__():
        if cls.FORMAT_NAME:
            parsers[cls.FORMAT_NAME] = cls
    return parsers

def get_parser(format_name: str, file_path: str, encoding: Optional[str] = None, custom_pattern: Optional[str] = None) -> BaseParser:
    """
    Factory function to instantiate the correct parser.
    """
    parsers = get_available_parsers()
    if format_name not in parsers:
        raise ValueError(f"Unknown format '{format_name}'. Available formats: {list(parsers.keys())}")
    
    parser_cls = parsers[format_name]
    # Pass custom_pattern only if the parser supports it in __init__
    return parser_cls(file_path, encoding=encoding, custom_pattern=custom_pattern)
