"""OgunScan core data models — Severity, Finding, ScanResult."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str
    remediation: str
    evidence: Optional[str] = None

    def identity(self) -> str:
        """Stable identity for diffing across scans. A finding is 'the same' if
        the rule and the location match — evidence/title may change as patterns
        evolve but the location is what changed in the customer's config."""
        return f"{self.rule_id}::{self.location}"


@dataclass
class ScanResult:
    target: str
    findings: List[Finding] = field(default_factory=list)
    scanned_servers: int = 0
    scanned_tools: int = 0

    @property
    def critical(self):
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high(self):
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium(self):
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low(self):
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def passed(self):
        return len(self.findings) == 0
