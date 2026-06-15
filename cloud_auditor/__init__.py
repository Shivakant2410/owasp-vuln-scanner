"""
Cloud Security Auditor — AWS Infrastructure Security Assessment Toolkit
========================================================================

A comprehensive cloud security auditing tool designed for offensive security
professionals. Performs automated security assessment of AWS infrastructure
including S3, IAM, EC2, networking, and logging configurations.

Also supports credential-less external reconnaissance for cloud asset discovery.

Author: Security Researcher
License: MIT
"""

__version__ = "1.2.0"
__author__ = "Cloud Security Auditor"

from cloud_auditor.core import CloudAuditor
from cloud_auditor.findings import Finding, Severity, FindingSet

__all__ = [
    "CloudAuditor",
    "Finding",
    "Severity",
    "FindingSet",
]
