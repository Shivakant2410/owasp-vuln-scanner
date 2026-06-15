"""
S3 Scanner — Bucket Security Assessment
========================================

Scans all S3 buckets in the target AWS account for misconfigurations
including public access, missing encryption, disabled versioning,
absent logging, and wildcard policy principals.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from cloud_auditor.findings import Finding, Severity


# Sensitive filename patterns often found in exposed buckets
SENSITIVE_PATTERNS = [
    ".env", ".git", "credentials", "secret", "password",
    "private", "backup", "database", ".pem", ".key",
    "id_rsa", "wp-config", "config.php", ".htpasswd",
]


class S3Scanner:
    """Scans S3 buckets for security misconfigurations.

    Attributes:
        session: Authenticated boto3 Session.
        region: AWS region for API calls.
    """

    def __init__(self, session: boto3.Session, region: str) -> None:
        self.session = session
        self.region = region
        self.s3 = session.client("s3", region_name=region)
        self.s3_control = session.client("s3control", region_name=region)

    def scan(self) -> list[Finding]:
        """Run all S3 security checks.

        Returns:
            List of Finding objects for each detected misconfiguration.
        """
        findings: list[Finding] = []

        try:
            buckets = self.s3.list_buckets()
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code == "AccessDenied":
                findings.append(
                    Finding(
                        title="Unable to list S3 buckets",
                        severity=Severity.INFO,
                        service="S3",
                        resource="s3:listbuckets",
                        detail="IAM policy denies s3:ListAllMyBuckets — scanner cannot enumerate buckets",
                        remediation="Grant s3:ListAllMyBuckets permission or use a read-only security audit role",
                    )
                )
                return findings
            raise

        bucket_list = buckets.get("Buckets", [])
        if not bucket_list:
            findings.append(
                Finding(
                    title="No S3 buckets found",
                    severity=Severity.INFO,
                    service="S3",
                    resource="account",
                    detail="No S3 buckets exist in this account",
                )
            )
            return findings

        for bucket_meta in bucket_list:
            bucket_name = bucket_meta["Name"]
            creation_date = bucket_meta.get("CreationDate", "")

            # 1. Check bucket ACL for public access
            findings.extend(self._check_acl(bucket_name))

            # 2. Check bucket policy for wildcard principals
            findings.extend(self._check_policy(bucket_name))

            # 3. Check encryption settings
            findings.extend(self._check_encryption(bucket_name))

            # 4. Check versioning status
            findings.extend(self._check_versioning(bucket_name))

            # 5. Check logging status
            findings.extend(self._check_logging(bucket_name))

            # 6. Check Block Public Access settings
            findings.extend(self._check_block_public_access(bucket_name))

            # 7. Check for sensitive file names (if listable)
            findings.extend(self._check_sensitive_files(bucket_name))

        return findings

    def _check_acl(self, bucket_name: str) -> list[Finding]:
        """Check bucket ACL for public read/write grants.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            List of findings for public ACL grants.
        """
        findings: list[Finding] = []

        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                return findings
            raise

        public_groups = {
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        }

        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")

            if uri in public_groups:
                group_label = "All Users (public)" if "AllUsers" in uri else "Authenticated AWS Users"
                permission = grant.get("Permission", "")

                severity = Severity.CRITICAL if "AllUsers" in uri else Severity.HIGH
                if permission == "WRITE":
                    severity = Severity.CRITICAL

                findings.append(
                    Finding(
                        title=f"Public ACL on S3 bucket: {bucket_name}",
                        severity=severity,
                        service="S3",
                        resource=bucket_name,
                        detail=f"Bucket grants {permission} access to {group_label}",
                        remediation=(
                            f"Remove the public grant from bucket '{bucket_name}' ACL. "
                            "Use: aws s3api put-bucket-acl --bucket {b} --acl private"
                        ),
                        compliance=["CIS 2.1", "CIS 2.2"],
                        region=self.region,
                    )
                )

        return findings

    def _check_policy(self, bucket_name: str) -> list[Finding]:
        """Check bucket policy for wildcard (*) principals.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            Findings for overly permissive bucket policies.
        """
        findings: list[Finding] = []

        try:
            policy_response = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response["Policy"]
            policy = json.loads(policy_str)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return findings
            if exc.response["Error"]["Code"] == "AccessDenied":
                return findings
            raise

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            principal = stmt.get("Principal", {})
            effect = stmt.get("Effect", "")

            if effect != "Allow":
                continue

            is_wildcard = False
            if isinstance(principal, str) and principal == "*":
                is_wildcard = True
            elif isinstance(principal, dict):
                if principal.get("AWS") == "*" or principal.get("Service") == "*":
                    is_wildcard = True
                elif isinstance(principal.get("AWS"), list) and "*" in principal["AWS"]:
                    is_wildcard = True

            if is_wildcard:
                action = stmt.get("Action", [])
                if isinstance(action, str):
                    action = [action]

                dangerous_actions = {"s3:GetObject", "s3:PutObject", "s3:*", "s3:*Object*"}
                has_dangerous = any(a in dangerous_actions for a in action) or "s3:*" in action

                severity = Severity.HIGH if has_dangerous else Severity.MEDIUM

                findings.append(
                    Finding(
                        title=f"Wildcard principal in bucket policy: {bucket_name}",
                        severity=severity,
                        service="S3",
                        resource=bucket_name,
                        detail=(
                            f"Policy allows {', '.join(action)} from '*' (any principal). "
                            f"Statement SID: {stmt.get('Sid', 'N/A')}"
                        ),
                        remediation=(
                            f"Restrict the Principal in bucket '{bucket_name}' policy to specific "
                            "AWS accounts, ARNs, or services. Avoid using '*'."
                        ),
                        compliance=["CIS 2.1"],
                        region=self.region,
                    )
                )

        return findings

    def _check_encryption(self, bucket_name: str) -> list[Finding]:
        """Check if bucket has default encryption enabled.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            Finding if encryption is not configured.
        """
        try:
            self.s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return [
                    Finding(
                        title=f"S3 bucket without default encryption: {bucket_name}",
                        severity=Severity.MEDIUM,
                        service="S3",
                        resource=bucket_name,
                        detail="Bucket does not have default server-side encryption configured",
                        remediation=(
                            f"Enable default encryption: "
                            f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                            f"--server-side-encryption-configuration "
                            f"'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":"
                            f'{{\"SSEAlgorithm\":\"AES256\"}}}}]}}\''
                        ),
                        compliance=["CIS 2.4"],
                        region=self.region,
                    )
                ]
            if exc.response["Error"]["Code"] == "AccessDenied":
                return []
            raise

        return []

    def _check_versioning(self, bucket_name: str) -> list[Finding]:
        """Check if bucket versioning is enabled.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            Finding if versioning is not enabled.
        """
        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                return []
            raise

        status = versioning.get("Status", "")
        if status != "Enabled":
            return [
                Finding(
                    title=f"S3 bucket without versioning: {bucket_name}",
                    severity=Severity.LOW,
                    service="S3",
                    resource=bucket_name,
                    detail=f"Versioning status is '{status or 'Suspended/Disabled'}' — data loss risk",
                    remediation=(
                        f"Enable versioning: "
                        f"aws s3api put-bucket-versioning --bucket {bucket_name} "
                        f"--versioning-configuration Status=Enabled"
                    ),
                    region=self.region,
                )
            ]

        return []

    def _check_logging(self, bucket_name: str) -> list[Finding]:
        """Check if bucket access logging is enabled.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            Finding if logging is not configured.
        """
        try:
            logging = self.s3.get_bucket_logging(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                return []
            raise

        if not logging.get("LoggingEnabled"):
            return [
                Finding(
                    title=f"S3 bucket without access logging: {bucket_name}",
                    severity=Severity.MEDIUM,
                    service="S3",
                    resource=bucket_name,
                    detail="Server access logging is not configured — forensic visibility gap",
                    remediation=(
                        f"Enable logging: "
                        f"aws s3api put-bucket-logging --bucket {bucket_name} "
                        f"--bucket-logging-status '{{\"LoggingEnabled\":{{"
                        f"\"TargetBucket\":\"log-bucket-name\","
                        f"\"TargetPrefix\":\"{bucket_name}/\"}}}}'"
                    ),
                    compliance=["CIS 2.6"],
                    region=self.region,
                )
            ]

        return []

    def _check_block_public_access(self, bucket_name: str) -> list[Finding]:
        """Check S3 Block Public Access settings at the bucket level.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            Finding if Block Public Access is not fully enabled.
        """
        try:
            pab = self.s3.get_public_access_block(
                Bucket=bucket_name,
            )
            config = pab["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDenied", "NoSuchPublicAccessBlockConfiguration"):
                # If no config exists, it means it's not explicitly set
                return [
                    Finding(
                        title=f"S3 bucket without Block Public Access: {bucket_name}",
                        severity=Severity.HIGH,
                        service="S3",
                        resource=bucket_name,
                        detail="No Block Public Access configuration found — bucket may be publicly accessible",
                        remediation=(
                            f"Enable all Block Public Access settings: "
                            f"aws s3api put-public-access-block --bucket {bucket_name} "
                            f"--public-access-block-configuration "
                            f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                            f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        compliance=["CIS 2.2"],
                        region=self.region,
                    )
                ]
            raise

        all_enabled = all(
            [
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ]
        )

        if not all_enabled:
            disabled_settings = [
                k for k, v in config.items() if v is False
            ]
            return [
                Finding(
                    title=f"S3 bucket with partial Block Public Access: {bucket_name}",
                    severity=Severity.MEDIUM,
                    service="S3",
                    resource=bucket_name,
                    detail=(
                        f"Block Public Access partially enabled. Disabled: {', '.join(disabled_settings)}"
                    ),
                    remediation="Enable all four Block Public Access settings for maximum protection",
                    compliance=["CIS 2.2"],
                    region=self.region,
                )
            ]

        return []

    def _check_sensitive_files(self, bucket_name: str) -> list[Finding]:
        """Attempt to list objects and flag sensitive file name patterns.

        This check is non-invasive — it only reads object keys, not content.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            Finding if sensitive file patterns are detected.
        """
        findings: list[Finding] = []

        try:
            response = self.s3.list_objects_v2(
                Bucket=bucket_name,
                MaxKeys=500,
            )
        except ClientError:
            # Access denied or other error — skip silently
            return findings

        objects = response.get("Contents", [])
        sensitive_found: list[str] = []

        for obj in objects:
            key = obj.get("Key", "").lower()
            for pattern in SENSITIVE_PATTERNS:
                if pattern in key:
                    sensitive_found.append(obj["Key"])
                    break

        if sensitive_found:
            findings.append(
                Finding(
                    title=f"Sensitive files detected in S3 bucket: {bucket_name}",
                    severity=Severity.HIGH,
                    service="S3",
                    resource=bucket_name,
                    detail=(
                        f"Found {len(sensitive_found)} files matching sensitive patterns: "
                        f"{', '.join(sensitive_found[:5])}"
                        f"{'...' if len(sensitive_found) > 5 else ''}"
                    ),
                    remediation=(
                        "Review and remove sensitive files. Rotate any exposed credentials immediately. "
                        "Enable encryption and restrict bucket access."
                    ),
                    region=self.region,
                )
            )

        return findings
