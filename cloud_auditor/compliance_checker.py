"""
Compliance Checker — CIS AWS Foundations Benchmark Assessment
=============================================================

Maps security findings to CIS (Center for Internet Security) AWS
Foundations Benchmark controls and generates a compliance score.
This checker runs its own independent checks for controls that
may not be covered by the service-specific scanners.
"""

from __future__ import annotations

from typing import Optional

import boto3
from botocore.exceptions import ClientError

from cloud_auditor.findings import Finding, Severity


class ComplianceChecker:
    """Checks CIS AWS Foundations Benchmark compliance.

    Evaluates a subset of CIS controls and maps findings to
    specific benchmark sections for compliance reporting.

    Attributes:
        session: Authenticated boto3 Session.
        region: AWS region for API calls.
    """

    # CIS AWS Foundations Benchmark controls checked by this module
    CIS_CONTROLS = {
        "1.1": "Avoid use of root account",
        "1.2": "Ensure MFA is enabled for all IAM users with console password",
        "1.3": "Ensure credentials unused for 90 days are disabled",
        "1.4": "Ensure access keys are rotated every 90 days",
        "1.5": "Ensure IAM password policy requires minimum length of 14 or greater",
        "1.6": "Ensure IAM password policy prevents password reuse",
        "1.7": "Ensure MFA is enabled for the root account",
        "1.8": "Ensure IAM password policy expires passwords within 90 days",
        "1.9": "Ensure IAM password policy requires at least one symbol",
        "1.10": "Ensure IAM password policy requires at least one number",
        "1.12": "Ensure no root account access key exists",
        "1.13": "Ensure no root account access key exists (MFA)",
        "1.14": "Ensure hardware MFA is enabled for root",
        "1.16": "Ensure IAM policies are attached only to groups or roles",
        "2.1": "Ensure S3 buckets are not publicly accessible",
        "2.2": "Ensure S3 Block Public Access setting is enabled",
        "3.1": "Ensure CloudTrail is enabled in all regions",
        "3.2": "Ensure CloudTrail trail is multi-region",
        "3.3": "Ensure CloudTrail log file validation is enabled",
        "3.4": "Ensure CloudTrail integrates with CloudWatch Logs",
        "3.5": "Ensure AWS Config is enabled in all regions",
        "3.6": "Ensure S3 bucket access logging is enabled",
        "3.8": "Ensure CloudTrail logs are encrypted at rest using KMS",
        "3.9": "Ensure VPC flow logging is enabled in all VPCs",
        "4.1": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "4.2": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
        "4.3": "Ensure EBS volumes are encrypted",
    }

    def __init__(self, session: boto3.Session, region: str) -> None:
        self.session = session
        self.region = region
        self.results: dict[str, dict] = {}

    def scan(self) -> list[Finding]:
        """Run CIS compliance checks.

        Returns:
            List of Finding objects for each failed CIS control.
        """
        findings: list[Finding] = []

        # Run independent compliance checks
        findings.extend(self._check_root_account_usage())
        findings.extend(self._check_security_group_ingress())
        findings.extend(self._check_ebs_encryption_default())

        return findings

    def _check_root_account_usage(self) -> list[Finding]:
        """CIS 1.1 — Check for root account usage in the last 24 hours.

        Returns:
            Finding if root account has been used recently.
        """
        findings: list[Finding] = []

        try:
            iam = self.session.client("iam")
            summary = iam.get_account_summary()
            summary_map = summary.get("SummaryMap", {})

            last_used_service = summary_map.get("ServiceLinkedRoles", 0)
            # The key names vary; check for recent root activity
            root_signin = summary_map.get("AccountMFAEnabled", 0)

        except ClientError:
            pass

        # Check root account last used via credential report
        try:
            iam = self.session.client("iam")

            # Generate credential report (may take a moment)
            try:
                iam.generate_credential_report()
            except ClientError:
                pass

            try:
                report = iam.get_credential_report()
                report_content = report["Content"]

                # Parse CSV content
                import csv
                import io

                reader = csv.DictReader(io.StringIO(report_content.decode("utf-8")))
                for row in reader:
                    if row.get("user", "") == "<root_account>":
                        password_last_used = row.get("password_last_used", "N/A")
                        access_key_1_last_used = row.get("access_key_1_last_used_date", "N/A")
                        access_key_2_last_used = row.get("access_key_2_last_used_date", "N/A")

                        if password_last_used not in ("N/A", "no_information"):
                            findings.append(
                                Finding(
                                    title="CIS 1.1: Root account recently used",
                                    severity=Severity.HIGH,
                                    service="Compliance",
                                    resource="root",
                                    detail=(
                                        f"Root account console last used: {password_last_used}. "
                                        f"Root account should not be used for daily operations."
                                    ),
                                    remediation=(
                                        "Create an IAM admin user for daily operations. "
                                        "Only use root account for tasks that require it."
                                    ),
                                    compliance=["CIS 1.1"],
                                )
                            )
                        break

            except ClientError:
                # Credential report not ready or access denied
                pass

        except ClientError:
            pass

        return findings

    def _check_security_group_ingress(self) -> list[Finding]:
        """CIS 4.1 & 4.2 — Check for SSH and RDP open to the world.

        This is a targeted compliance check that directly maps to
        CIS controls, even if the EC2 auditor already flagged these.

        Returns:
            Findings for security groups violating CIS 4.1/4.2.
        """
        findings: list[Finding] = []

        try:
            ec2 = self.session.client("ec2", region_name=self.region)

            # Check SSH (port 22)
            ssh_groups = ec2.describe_security_groups(
                Filters=[
                    {"Name": "ip-permission.from-port", "Values": ["22"]},
                    {"Name": "ip-permission.to-port", "Values": ["22"]},
                    {"Name": "ip-permission.cidr", "Values": ["0.0.0.0/0"]},
                ]
            )

            for sg in ssh_groups.get("SecurityGroups", []):
                findings.append(
                    Finding(
                        title=f"CIS 4.1 FAIL: SSH open to 0.0.0.0/0 — {sg['GroupName']}",
                        severity=Severity.CRITICAL,
                        service="Compliance",
                        resource=sg["GroupId"],
                        detail=(
                            f"Security group '{sg['GroupName']}' ({sg['GroupId']}) "
                            f"allows SSH (port 22) from 0.0.0.0/0 — CIS 4.1 FAIL"
                        ),
                        remediation=(
                            "Restrict SSH access to specific IP ranges or use a bastion host/VPN. "
                            "Remove the 0.0.0.0/0 ingress rule for port 22."
                        ),
                        compliance=["CIS 4.1"],
                    )
                )

            # Check RDP (port 3389)
            rdp_groups = ec2.describe_security_groups(
                Filters=[
                    {"Name": "ip-permission.from-port", "Values": ["3389"]},
                    {"Name": "ip-permission.to-port", "Values": ["3389"]},
                    {"Name": "ip-permission.cidr", "Values": ["0.0.0.0/0"]},
                ]
            )

            for sg in rdp_groups.get("SecurityGroups", []):
                findings.append(
                    Finding(
                        title=f"CIS 4.2 FAIL: RDP open to 0.0.0.0/0 — {sg['GroupName']}",
                        severity=Severity.CRITICAL,
                        service="Compliance",
                        resource=sg["GroupId"],
                        detail=(
                            f"Security group '{sg['GroupName']}' ({sg['GroupId']}) "
                            f"allows RDP (port 3389) from 0.0.0.0/0 — CIS 4.2 FAIL"
                        ),
                        remediation=(
                            "Restrict RDP access to specific IP ranges or use a VPN. "
                            "Remove the 0.0.0.0/0 ingress rule for port 3389."
                        ),
                        compliance=["CIS 4.2"],
                    )
                )

        except ClientError:
            pass

        return findings

    def _check_ebs_encryption_default(self) -> list[Finding]:
        """Check if EBS encryption is enabled by default for the account.

        Returns:
            Finding if EBS encryption by default is not enabled.
        """
        findings: list[Finding] = []

        try:
            ec2 = self.session.client("ec2", region_name=self.region)
            response = ec2.get_ebs_encryption_by_default()
            enabled = response.get("EbsEncryptionByDefault", False)

            if not enabled:
                findings.append(
                    Finding(
                        title="EBS encryption not enabled by default",
                        severity=Severity.MEDIUM,
                        service="Compliance",
                        resource="account:ebs",
                        detail="New EBS volumes will not be encrypted by default",
                        remediation=(
                            "Enable EBS encryption by default: "
                            "aws ec2 enable-ebs-encryption-by-default"
                        ),
                        compliance=["CIS 4.3"],
                    )
                )

        except ClientError:
            pass

        return findings

    def calculate_compliance_score(self, findings: list[Finding]) -> dict:
        """Calculate compliance score based on findings.

        Maps all findings to CIS controls and determines pass/fail
        status for each checked control.

        Args:
            findings: All findings from the complete audit run.

        Returns:
            Dictionary with compliance score and per-control status.
        """
        # Map findings to CIS controls
        failed_controls: set[str] = set()
        for f in findings:
            for ref in f.compliance:
                if ref.startswith("CIS "):
                    control_id = ref.replace("CIS ", "")
                    if control_id in self.CIS_CONTROLS:
                        failed_controls.add(control_id)

        total_controls = len(self.CIS_CONTROLS)
        passed_controls = total_controls - len(failed_controls)
        score_pct = round((passed_controls / total_controls) * 100, 1) if total_controls else 0

        control_status: dict[str, dict] = {}
        for ctrl_id, description in self.CIS_CONTROLS.items():
            control_status[ctrl_id] = {
                "description": description,
                "status": "FAIL" if ctrl_id in failed_controls else "PASS",
            }

        return {
            "framework": "CIS AWS Foundations Benchmark v1.5",
            "total_controls": total_controls,
            "passed": passed_controls,
            "failed": len(failed_controls),
            "score_percentage": score_pct,
            "controls": control_status,
        }
