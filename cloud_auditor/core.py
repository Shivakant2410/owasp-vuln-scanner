"""
Core Module — Main CloudAuditor orchestrator
=============================================

Central orchestrator that initializes AWS sessions, coordinates all
security scanners, and aggregates findings into a unified report.
"""

from __future__ import annotations

import sys
import datetime
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
from colorama import init as colorama_init
from tqdm import tqdm

from cloud_auditor.findings import Finding, Severity, FindingSet
from cloud_auditor.s3_scanner import S3Scanner
from cloud_auditor.iam_analyzer import IAMAnalyzer
from cloud_auditor.ec2_auditor import EC2Auditor
from cloud_auditor.network_auditor import NetworkAuditor
from cloud_auditor.logging_checker import LoggingChecker
from cloud_auditor.compliance_checker import ComplianceChecker
from cloud_auditor.report_generator import ReportGenerator

# Initialize colorama for cross-platform color support
colorama_init(autoreset=True)


class CloudAuditor:
    """Orchestrates a full cloud security assessment against an AWS account.

    This class manages AWS session creation, runs each scanner module,
    and collects all findings into a unified FindingSet for reporting.

    Attributes:
        profile: AWS CLI profile name.
        region: AWS region to scan.
        session: Authenticated boto3 Session.
        findings: Aggregated FindingSet from all scanners.
    """

    SERVICES = ["s3", "iam", "ec2", "network", "logging", "compliance"]

    def __init__(self, profile: str = "default", region: str = "us-east-1") -> None:
        """Initialize the CloudAuditor with AWS profile and region.

        Args:
            profile: AWS CLI named profile for credentials.
            region: Default AWS region for API calls.
        """
        self.profile = profile
        self.region = region
        self.session: Optional[boto3.Session] = None
        self.account_id: str = ""
        self.findings = FindingSet()
        self._authenticated = False

    def _init_session(self) -> bool:
        """Create and validate a boto3 session.

        Returns:
            True if session is valid and credentials work, False otherwise.
        """
        try:
            self.session = boto3.Session(
                profile_name=self.profile,
                region_name=self.region,
            )
            # Validate credentials by calling STS
            sts = self.session.client("sts")
            identity = sts.get_caller_identity()
            self.account_id = identity["Account"]
            self._authenticated = True
            return True
        except (NoCredentialsError, BotoCoreError) as exc:
            print(f"\033[91m[!] AWS credentials error: {exc}\033[0m")
            print("\033[33m[*] Tip: Use --standalone mode for external recon without AWS creds\033[0m")
            return False
        except ClientError as exc:
            print(f"\033[91m[!] AWS API error: {exc}\033[0m")
            return False
        except Exception as exc:
            print(f"\033[91m[!] Unexpected error: {exc}\033[0m")
            return False

    def _print_banner(self) -> None:
        """Display the auditor banner."""
        banner = r"""
 ╔═══════════════════════════════════════════════════════════╗
 ║          ☁️  CLOUD SECURITY AUDITOR v1.2.0  ☁️            ║
 ║         AWS Infrastructure Security Assessment            ║
 ╠═══════════════════════════════════════════════════════════╣
 ║  Target:  {account:<45} ║
 ║  Region:  {region:<45} ║
 ║  Time:    {timestamp:<45} ║
 ╚═══════════════════════════════════════════════════════════╝
""".format(
            account=f"AWS Account: {self.account_id or 'N/A'}",
            region=self.region,
            timestamp=datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
        )
        print(banner)

    def run(self, services: Optional[list[str]] = None) -> FindingSet:
        """Execute the full security audit.

        Args:
            services: Optional list of specific services to scan.
                      If None, runs all scanners.

        Returns:
            FindingSet containing all discovered security findings.
        """
        if not self._init_session():
            return self.findings

        self._print_banner()

        self.findings.account_id = self.account_id
        self.findings.scan_target = f"AWS Account {self.account_id}"
        self.findings.scan_timestamp = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()

        if services is None:
            services = self.SERVICES

        # Validate requested services
        invalid = set(services) - set(self.SERVICES)
        if invalid:
            print(f"\033[33m[!] Unknown services ignored: {', '.join(invalid)}\033[0m")
            services = [s for s in services if s in self.SERVICES]

        print(f"\n\033[1m[*] Running security assessment for: {', '.join(services)}\033[0m\n")

        scanner_map = {
            "s3": self._run_s3,
            "iam": self._run_iam,
            "ec2": self._run_ec2,
            "network": self._run_network,
            "logging": self._run_logging,
            "compliance": self._run_compliance,
        }

        with tqdm(total=len(services), desc="Auditing", unit="service") as pbar:
            for svc in services:
                if svc in scanner_map:
                    try:
                        scanner_map[svc](pbar)
                    except ClientError as exc:
                        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
                        print(
                            f"\033[33m[!] {svc.upper()} scan skipped — "
                            f"API error ({error_code}). Insufficient permissions?\033[0m"
                        )
                        pbar.update(1)
                    except Exception as exc:
                        print(f"\033[33m[!] {svc.upper()} scan error: {exc}\033[0m")
                        pbar.update(1)
                else:
                    pbar.update(1)

        # Run compliance mapping on all findings
        if "compliance" in services:
            self._map_compliance()

        return self.findings

    def _run_s3(self, pbar: tqdm) -> None:
        """Run S3 bucket security scanner."""
        pbar.set_postfix_str("S3 Buckets")
        scanner = S3Scanner(self.session, self.region)
        findings = scanner.scan()
        self.findings.extend(findings)
        pbar.update(1)

    def _run_iam(self, pbar: tqdm) -> None:
        """Run IAM security analyzer."""
        pbar.set_postfix_str("IAM Users & Policies")
        scanner = IAMAnalyzer(self.session, self.region)
        findings = scanner.scan()
        self.findings.extend(findings)
        pbar.update(1)

    def _run_ec2(self, pbar: tqdm) -> None:
        """Run EC2 security auditor."""
        pbar.set_postfix_str("EC2 Instances & Volumes")
        scanner = EC2Auditor(self.session, self.region)
        findings = scanner.scan()
        self.findings.extend(findings)
        pbar.update(1)

    def _run_network(self, pbar: tqdm) -> None:
        """Run network security auditor."""
        pbar.set_postfix_str("VPC & Network")
        scanner = NetworkAuditor(self.session, self.region)
        findings = scanner.scan()
        self.findings.extend(findings)
        pbar.update(1)

    def _run_logging(self, pbar: tqdm) -> None:
        """Run logging and monitoring checker."""
        pbar.set_postfix_str("CloudTrail & Logging")
        scanner = LoggingChecker(self.session, self.region)
        findings = scanner.scan()
        self.findings.extend(findings)
        pbar.update(1)

    def _run_compliance(self, pbar: tqdm) -> None:
        """Run CIS compliance checks."""
        pbar.set_postfix_str("CIS Compliance")
        checker = ComplianceChecker(self.session, self.region)
        findings = checker.scan()
        self.findings.extend(findings)
        pbar.update(1)

    def _map_compliance(self) -> None:
        """Map existing findings to CIS controls for cross-referencing."""
        cis_map = {
            "s3": ["2.1", "2.2", "2.3", "2.4", "2.5", "2.6"],
            "iam": ["1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10"],
            "logging": ["3.1", "3.2", "3.3", "3.4"],
            "ec2": ["4.1", "4.2"],
        }
        # Compliance findings are already generated by ComplianceChecker
        # This method is reserved for future cross-referencing logic
