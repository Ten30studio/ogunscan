"""OgunScan — MCP Server Security Scanner.

Built by Ten30 Studio. Named for Ogun, Yoruba orisha of iron and protection.

Public API (stable across the 0.1.x line):

  from ogunscan import OgunScanner, Severity, Finding, ScanResult, format_report
"""

__version__ = "0.2.0"

from .engine import OgunScanner
from .models import Finding, ScanResult, Severity
from .reporter import format_report
from .cli import cli

__all__ = [
    "OgunScanner",
    "Finding",
    "ScanResult",
    "Severity",
    "format_report",
    "cli",
    "__version__",
]
