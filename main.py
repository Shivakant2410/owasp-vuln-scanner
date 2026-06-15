#!/usr/bin/env python3
"""
Cloud Security Auditor — CLI Entry Point
=========================================

Command-line interface for running cloud security assessments.
Supports both authenticated AWS audits and credential-less
external reconnaissance modes.

Usage:
    # Full AWS audit (requires AWS credentials)
    python main.py --profile default --region us-east-1

    # Specific service audit
    python main.py --profile default --service s3 --service iam

    # Output as JSON report
    python main.py --profile default --output json --output-file report.json

    # External reconnaissance (no AWS credentials needed)
    python main.py --standalone --domain example.com

    # Full audit with HTML report
    python main.py --profile default --output html --output-file report.html
"""

from __future__ import annotations

import argparse
import datetime
import sys
from typing import Optional

from cloud_auditor.core import CloudAuditor
from cloud_auditor.external_recon import ExternalRecon
from cloud_auditor.findings import FindingSet, Severity
from cloud_auditor.report_generator import ReportGenerator
from cloud_auditor.compliance_checker import ComplianceChecker

BANNER = r"""
 ╔═══════════════════════════════════════════════════════════╗
 ║          ☁️  CLOUD SECURITY AUDITOR v1.2.0  ☁️            ║
 ║         AWS Infrastructure Security Assessment            ║
 ╚═══════════════════════════════════════════════════════════╝
"""


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description="Cloud Security Auditor — AWS Infrastructure Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --profile default --region us-east-1\n"
            "  python main.py --profile default --service s3 --service iam\n"
            "  python main.py --profile default --output json --output-file report.json\n"
            "  python main.py --standalone --domain example.com\n"
            "  python main.py --standalone --domain example.com --output html --output-file report.html\n"
        ),
    )

    # Authentication options
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--profile",
        default="default",
        help="AWS CLI profile name (default: default)",
    )
    auth_group.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region to scan (default: us-east-1)",
    )

    # Standalone mode
    standalone_group = parser.add_argument_group("Standalone Mode (No AWS Credentials)")
    standalone_group.add_argument(
        "--standalone",
        action="store_true",
        help="Run external reconnaissance without AWS credentials",
    )
    standalone_group.add_argument(
        "--domain",
        help="Target domain for standalone external reconnaissance",
    )

    # Service selection
    service_group = parser.add_argument_group("Service Selection")
    service_group.add_argument(
        "--service",
        action="append",
        dest="services",
        choices=["s3", "iam", "ec2", "network", "logging", "compliance"],
        help="Specific service(s) to audit (can be repeated). Default: all services",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output",
        choices=["console", "json", "html", "both"],
        default="console",
        help="Output format (default: console). 'both' outputs JSON + HTML",
    )
    output_group.add_argument(
        "--output-file",
        help="Output file path for JSON/HTML reports",
    )

    # Display options
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress banner and progress output",
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="INFO",
        help="Minimum severity level to display (default: INFO)",
    )

    return parser.parse_args()


def run_aws_audit(args: argparse.Namespace) -> FindingSet:
    """Run the authenticated AWS security audit.

    Args:
        args: Parsed CLI arguments.

    Returns:
        FindingSet with all audit results.
    """
    auditor = CloudAuditor(profile=args.profile, region=args.region)
    findings = auditor.run(services=args.services)

    return findings


def run_standalone_recon(args: argparse.Namespace) -> FindingSet:
    """Run standalone external reconnaissance.

    Args:
        args: Parsed CLI arguments.

    Returns:
        FindingSet with reconnaissance results.
    """
    if not args.domain:
        print("\033[91m[!] --domain is required for standalone mode\033[0m")
        print("    Usage: python main.py --standalone --domain example.com")
        sys.exit(1)

    recon = ExternalRecon(domain=args.domain)
    findings_list = recon.scan()

    # Wrap in a FindingSet
    finding_set = FindingSet()
    finding_set.account_id = "N/A (External Recon)"
    finding_set.scan_target = args.domain
    finding_set.scan_timestamp = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
    finding_set.extend(findings_list)

    return finding_set


def filter_by_severity(findings: FindingSet, min_severity: str) -> FindingSet:
    """Filter findings by minimum severity level.

    Args:
        findings: Original finding set.
        min_severity: Minimum severity level string.

    Returns:
        Filtered FindingSet.
    """
    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    min_level = severity_order.get(min_severity, 4)
    filtered = FindingSet()
    filtered.account_id = findings.account_id
    filtered.scan_target = findings.scan_target
    filtered.scan_timestamp = findings.scan_timestamp

    for finding in findings.findings:
        if severity_order.get(finding.severity.value, 4) <= min_level:
            filtered.add(finding)

    return filtered


def generate_reports(
    findings: FindingSet,
    args: argparse.Namespace,
) -> None:
    """Generate output reports based on CLI arguments.

    Args:
        findings: The complete finding set.
        args: Parsed CLI arguments.
    """
    # Filter by severity
    filtered = filter_by_severity(findings, args.min_severity)

    output_format = args.output

    # Console output
    if output_format in ("console", "both"):
        print(filtered.to_console())

        # Print remediation priority list
        critical_and_high = [
            f for f in filtered.sorted_by_severity()
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        if critical_and_high:
            print("\n\033[1m⚠️  PRIORITY REMEDIATION LIST\033[0m")
            print("=" * 50)
            for i, f in enumerate(critical_and_high[:10], 1):
                print(f"  {i}. {f.severity.color}[{f.severity.value}]\033[0m {f.title}")
                if f.remediation:
                    print(f"     → {f.remediation}")
            if len(critical_and_high) > 10:
                print(f"  ... and {len(critical_and_high) - 10} more")
            print()

    # Calculate compliance score
    compliance_data = None
    if not args.standalone:
        try:
            # Create a temporary session for compliance scoring
            import boto3
            session = boto3.Session(profile_name=args.profile, region_name=args.region)
            checker = ComplianceChecker(session, args.region)
            compliance_data = checker.calculate_compliance_score(filtered.findings)
        except Exception:
            pass

    # JSON output
    if output_format in ("json", "both"):
        gen = ReportGenerator(filtered, compliance=compliance_data)
        filepath = args.output_file or "audit_report.json"
        path = gen.export_json(filepath)
        print(f"\033[32m[+] JSON report saved to: {path}\033[0m")

    # HTML output
    if output_format in ("html", "both"):
        gen = ReportGenerator(filtered, compliance=compliance_data)
        filepath = args.output_file or "audit_report.html"
        path = gen.export_html(filepath)
        print(f"\033[32m[+] HTML report saved to: {path}\033[0m")


def main() -> None:
    """Main entry point for the Cloud Security Auditor CLI."""
    args = parse_args()

    if not args.quiet:
        print(BANNER)

    try:
        if args.standalone:
            findings = run_standalone_recon(args)
        else:
            findings = run_aws_audit(args)

        generate_reports(findings, args)

        # Exit with non-zero code if critical findings exist
        has_critical = any(
            f.severity == Severity.CRITICAL for f in findings.findings
        )
        if has_critical:
            sys.exit(2)

        has_high = any(
            f.severity == Severity.HIGH for f in findings.findings
        )
        if has_high:
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\033[33m[!] Audit interrupted by user\033[0m")
        sys.exit(130)
    except Exception as exc:
        print(f"\033[91m[!] Fatal error: {exc}\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    main()
