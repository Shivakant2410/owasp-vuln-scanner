"""
Findings Module — Data structures for security assessment results
=================================================================

Defines Finding, Severity, and FindingSet classes used across all scanners
to maintain consistent reporting and risk scoring.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Risk severity levels aligned with CVSS qualitative ratings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Numeric weight for risk scoring calculations."""
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return weights[self]

    @property
    def color(self) -> str:
        """ANSI color code for terminal output."""
        colors = {
            Severity.CRITICAL: "\033[91m",   # bright red
            Severity.HIGH: "\033[31m",       # red
            Severity.MEDIUM: "\033[33m",     # yellow
            Severity.LOW: "\033[36m",        # cyan
            Severity.INFO: "\033[37m",       # white
        }
        return colors[self]

    @property
    def html_color(self) -> str:
        """Hex color code for HTML reports."""
        colors = {
            Severity.CRITICAL: "#ff4444",
            Severity.HIGH: "#ff6b6b",
            Severity.MEDIUM: "#ffd93d",
            Severity.LOW: "#6bcbff",
            Severity.INFO: "#aaaaaa",
        }
        return colors[self]

    def __str__(self) -> str:
        return self.value


RESET = "\033[0m"
BOLD = "\033[1m"


@dataclass
class Finding:
    """Represents a single security finding from an audit check.

    Attributes:
        title: Short descriptive title of the finding.
        severity: Risk severity level.
        service: AWS service (e.g. 'S3', 'IAM', 'EC2').
        resource: Affected resource identifier.
        detail: Detailed explanation of the finding.
        remediation: Suggested fix or next step.
        compliance: List of compliance framework references (e.g. CIS 2.1).
        region: AWS region of the affected resource.
    """

    title: str
    severity: Severity
    service: str
    resource: str
    detail: str = ""
    remediation: str = ""
    compliance: list[str] = field(default_factory=list)
    region: str = ""

    def to_dict(self) -> dict:
        """Convert finding to a JSON-serializable dictionary."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "service": self.service,
            "resource": self.resource,
            "detail": self.detail,
            "remediation": self.remediation,
            "compliance": self.compliance,
            "region": self.region,
        }

    def to_console(self) -> str:
        """Format finding for color-coded terminal output."""
        color = self.severity.color
        severity_tag = f"{color}{BOLD}[{self.severity.value}]{RESET}"
        lines = [
            f"  {severity_tag} {self.title}",
            f"    Service:   {self.service}",
            f"    Resource:  {self.resource}",
        ]
        if self.detail:
            lines.append(f"    Detail:    {self.detail}")
        if self.remediation:
            lines.append(f"    Fix:       {self.remediation}")
        if self.compliance:
            lines.append(f"    Compliance:{' '.join(self.compliance)}")
        if self.region:
            lines.append(f"    Region:    {self.region}")
        return "\n".join(lines)


@dataclass
class FindingSet:
    """Collection of findings with aggregate risk scoring.

    Provides methods for filtering, scoring, and exporting findings
    across a complete audit run.
    """

    findings: list[Finding] = field(default_factory=list)
    account_id: str = ""
    scan_target: str = ""
    scan_timestamp: str = ""

    def add(self, finding: Finding) -> None:
        """Add a finding to the set."""
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        """Add multiple findings to the set."""
        self.findings.extend(findings)

    @property
    def total(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def risk_score(self) -> float:
        """Calculate aggregate risk score (0-100 scale).

        Uses weighted severity with diminishing returns so that
        many low findings don't overshadow a few critical ones.
        """
        if not self.findings:
            return 0.0
        raw = sum(f.severity.weight for f in self.findings)
        # Normalize: sigmoid-like scaling so score stays in 0-100
        max_possible = len(self.findings) * 10
        if max_possible == 0:
            return 0.0
        normalized = (raw / max_possible) * 100
        return round(min(normalized, 100.0), 1)

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count of findings per severity level."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def by_severity(self, severity: Severity) -> list[Finding]:
        """Filter findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def by_service(self, service: str) -> list[Finding]:
        """Filter findings by AWS service."""
        return [f for f in self.findings if f.service.lower() == service.lower()]

    def sorted_by_severity(self) -> list[Finding]:
        """Return findings sorted by severity (most severe first)."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(self.findings, key=lambda f: order[f.severity])

    def to_dict(self) -> dict:
        """Convert entire finding set to a JSON-serializable dictionary."""
        return {
            "account_id": self.account_id,
            "scan_target": self.scan_target,
            "scan_timestamp": self.scan_timestamp,
            "risk_score": self.risk_score,
            "severity_counts": self.severity_counts,
            "total_findings": self.total,
            "findings": [f.to_dict() for f in self.sorted_by_severity()],
        }

    def to_json(self, indent: int = 2) -> str:
        """Export findings as formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_console(self) -> str:
        """Format entire finding set for terminal output."""
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append(f"  CLOUD SECURITY AUDIT RESULTS")
        lines.append(f"{'='*60}")
        lines.append(f"  Account:   {self.account_id or 'N/A'}")
        lines.append(f"  Target:    {self.scan_target or 'N/A'}")
        lines.append(f"  Time:      {self.scan_timestamp or 'N/A'}")
        lines.append(f"{'─'*60}")
        lines.append(f"  Risk Score: {self.risk_score}/100")
        lines.append(f"  Total Findings: {self.total}")
        for sev, count in self.severity_counts.items():
            sev_obj = Severity(sev)
            lines.append(f"    {sev_obj.color}{sev}: {count}{RESET}")
        lines.append(f"{'='*60}\n")

        for finding in self.sorted_by_severity():
            lines.append(finding.to_console())
            lines.append("")

        return "\n".join(lines)
