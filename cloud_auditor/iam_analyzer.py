"""
IAM Analyzer — Identity and Access Management Security Assessment
=================================================================

Analyzes IAM configurations for security weaknesses including
over-privileged users, missing MFA, stale credentials, and
admin-level access misconfigurations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from cloud_auditor.findings import Finding, Severity


# IAM actions that indicate administrative privileges
ADMIN_ACTIONS = {
    "iam:*", "ec2:*", "s3:*", "*:*", "sts:*",
    "cloudformation:*", "lambda:*", "dynamodb:*",
    "rds:*", "kms:*", "secretsmanager:*",
}

# Policy document patterns that indicate admin access
ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

MAX_KEY_AGE_DAYS = 90
MAX_CREDENTIAL_UNUSED_DAYS = 90


class IAMAnalyzer:
    """Scans IAM users, policies, and credentials for security issues.

    Attributes:
        session: Authenticated boto3 Session.
        region: AWS region for API calls.
    """

    def __init__(self, session: boto3.Session, region: str) -> None:
        self.session = session
        self.region = region
        self.iam = session.client("iam")

    def scan(self) -> list[Finding]:
        """Run all IAM security checks.

        Returns:
            List of Finding objects for each IAM misconfiguration.
        """
        findings: list[Finding] = []

        # 1. Check root account usage
        findings.extend(self._check_root_usage())

        # 2. Check users without MFA
        findings.extend(self._check_mfa())

        # 3. Check for old access keys
        findings.extend(self._check_access_key_age())

        # 4. Check for admin privileges
        findings.extend(self._check_admin_privileges())

        # 5. Check for unused credentials
        findings.extend(self._check_unused_credentials())

        # 6. Check for inline policies
        findings.extend(self._check_inline_policies())

        # 7. Check password policy
        findings.extend(self._check_password_policy())

        return findings

    def _check_root_usage(self) -> list[Finding]:
        """Check for recent root account activity.

        Returns:
            Finding if root account has been used recently.
        """
        findings: list[Finding] = []

        try:
            summary = self.iam.get_account_summary()
            summary_map = summary.get("SummaryMap", {})

            root_access_keys = summary_map.get("AccountAccessKeysPresent", 0)
            root_mfa = summary_map.get("AccountMFAEnabled", 0)

            if root_access_keys > 0:
                findings.append(
                    Finding(
                        title="Root account has active access keys",
                        severity=Severity.CRITICAL,
                        service="IAM",
                        resource="root",
                        detail=f"Root account has {root_access_keys} access key(s) — violates least privilege",
                        remediation=(
                            "Delete root access keys immediately: "
                            "aws iam delete-access-key --access-key-id <KEY_ID> --user-name root. "
                            "Use IAM users or roles instead."
                        ),
                        compliance=["CIS 1.12"],
                    )
                )

            if root_mfa == 0:
                findings.append(
                    Finding(
                        title="Root account does not have MFA enabled",
                        severity=Severity.CRITICAL,
                        service="IAM",
                        resource="root",
                        detail="Root account MFA is not enabled — critical security gap",
                        remediation=(
                            "Enable MFA on the root account immediately via the AWS Console. "
                            "Use a hardware MFA device for the root account."
                        ),
                        compliance=["CIS 1.13"],
                    )
                )

        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    Finding(
                        title="Cannot check root account status",
                        severity=Severity.INFO,
                        service="IAM",
                        resource="root",
                        detail="Insufficient permissions to check root account MFA and access keys",
                        remediation="Grant iam:GetAccountSummary permission",
                    )
                )

        return findings

    def _check_mfa(self) -> list[Finding]:
        """Check for IAM users without MFA devices.

        Returns:
            Findings for each user missing MFA.
        """
        findings: list[Finding] = []

        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]

                    # Skip users without console access (no password)
                    try:
                        login_profile = self.iam.get_login_profile(UserName=username)
                        has_console = True
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] == "NoSuchEntity":
                            has_console = False
                        else:
                            continue

                    if not has_console:
                        continue

                    # Check MFA devices
                    mfa_devices = self.iam.list_mfa_devices(UserName=username)
                    if not mfa_devices.get("MFADevices"):
                        findings.append(
                            Finding(
                                title=f"IAM user without MFA: {username}",
                                severity=Severity.HIGH,
                                service="IAM",
                                resource=f"user:{username}",
                                detail=f"User '{username}' has console access but no MFA device configured",
                                remediation=(
                                    f"Enable MFA for user '{username}': "
                                    f"aws iam enable-mfa-device --user-name {username} "
                                    f"--serial-number arn:aws:iam::... --authentication-code1 <code>"
                                ),
                                compliance=["CIS 1.10"],
                            )
                        )

        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    Finding(
                        title="Cannot list IAM users for MFA check",
                        severity=Severity.INFO,
                        service="IAM",
                        resource="iam:listusers",
                        detail="Insufficient permissions to enumerate IAM users",
                        remediation="Grant iam:ListUsers and iam:ListMFADevices permissions",
                    )
                )

        return findings

    def _check_access_key_age(self) -> list[Finding]:
        """Check for access keys older than 90 days.

        Returns:
            Findings for each stale access key.
        """
        findings: list[Finding] = []
        now = datetime.now(timezone.utc)

        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]

                    try:
                        keys_response = self.iam.list_access_keys(UserName=username)
                    except ClientError:
                        continue

                    for key in keys_response.get("AccessKeyMetadata", []):
                        if key.get("Status") != "Active":
                            continue

                        create_date = key.get("CreateDate", now)
                        age_days = (now - create_date).days

                        if age_days > MAX_KEY_AGE_DAYS:
                            findings.append(
                                Finding(
                                    title=f"Old access key on user: {username}",
                                    severity=Severity.MEDIUM,
                                    service="IAM",
                                    resource=f"user:{username}/key:{key['AccessKeyId']}",
                                    detail=(
                                        f"Active access key {key['AccessKeyId']} is {age_days} days old "
                                        f"(threshold: {MAX_KEY_AGE_DAYS} days)"
                                    ),
                                    remediation=(
                                        f"Rotate the access key for user '{username}'. "
                                        f"Create a new key, update applications, then deactivate the old key."
                                    ),
                                    compliance=["CIS 1.4"],
                                )
                            )

        except ClientError:
            pass

        return findings

    def _check_admin_privileges(self) -> list[Finding]:
        """Check for users with AdministratorAccess or equivalent policies.

        Returns:
            Findings for each user with admin-level access.
        """
        findings: list[Finding] = []

        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]

                    # Check attached policies
                    try:
                        attached = self.iam.list_attached_user_policies(UserName=username)
                        for policy in attached.get("AttachedPolicies", []):
                            policy_arn = policy.get("PolicyArn", "")
                            policy_name = policy.get("PolicyName", "")

                            if "Admin" in policy_name or policy_arn in ADMIN_POLICY_ARNS:
                                findings.append(
                                    Finding(
                                        title=f"User with admin policy: {username}",
                                        severity=Severity.HIGH,
                                        service="IAM",
                                        resource=f"user:{username}",
                                        detail=f"User has attached policy '{policy_name}' ({policy_arn})",
                                        remediation=(
                                            f"Review if user '{username}' truly needs admin access. "
                                            f"Apply least-privilege scoped policies instead."
                                        ),
                                        compliance=["CIS 1.16"],
                                    )
                                )
                    except ClientError:
                        continue

                    # Check inline policies for admin-level actions
                    try:
                        inline_policies = self.iam.list_user_policies(UserName=username)
                        for policy_name in inline_policies.get("PolicyNames", []):
                            doc = self.iam.get_user_policy(
                                UserName=username, PolicyName=policy_name
                            )
                            policy_doc = doc.get("PolicyDocument", {})
                            if self._policy_has_admin_actions(policy_doc):
                                findings.append(
                                    Finding(
                                        title=f"User with admin inline policy: {username}",
                                        severity=Severity.HIGH,
                                        service="IAM",
                                        resource=f"user:{username}/policy:{policy_name}",
                                        detail=(
                                            f"Inline policy '{policy_name}' grants admin-level actions"
                                        ),
                                        remediation=(
                                            f"Replace inline policy with a scoped managed policy. "
                                            f"Avoid inline policies for production accounts."
                                        ),
                                        compliance=["CIS 1.16"],
                                    )
                                )
                    except ClientError:
                        continue

        except ClientError:
            pass

        return findings

    def _check_unused_credentials(self) -> list[Finding]:
        """Check for IAM users with unused credentials (90+ days).

        Returns:
            Findings for each user with unused credentials.
        """
        findings: list[Finding] = []
        now = datetime.now(timezone.utc)

        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]

                    try:
                        credential_report = self.iam.generate_credential_report()
                    except ClientError:
                        pass

                    # Use last_used information from get_user
                    try:
                        user_detail = self.iam.get_user(UserName=username)
                        user_info = user_detail.get("User", {})
                        password_last_used = user_info.get("PasswordLastUsed")

                        # Check console password not used in 90 days
                        if password_last_used:
                            unused_days = (now - password_last_used).days
                            if unused_days > MAX_CREDENTIAL_UNUSED_DAYS:
                                findings.append(
                                    Finding(
                                        title=f"Unused console credentials: {username}",
                                        severity=Severity.MEDIUM,
                                        service="IAM",
                                        resource=f"user:{username}",
                                        detail=(
                                            f"Console password last used {unused_days} days ago "
                                            f"(threshold: {MAX_CREDENTIAL_UNUSED_DAYS} days)"
                                        ),
                                        remediation=(
                                            f"Review if user '{username}' still needs access. "
                                            f"Deactivate or remove unused accounts."
                                        ),
                                        compliance=["CIS 1.3"],
                                    )
                                )
                    except ClientError:
                        continue

        except ClientError:
            pass

        return findings

    def _check_inline_policies(self) -> list[Finding]:
        """Check for IAM users with inline policies.

        Inline policies are harder to audit and maintain than managed policies.

        Returns:
            Findings for each user with inline policies.
        """
        findings: list[Finding] = []

        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]

                    try:
                        inline = self.iam.list_user_policies(UserName=username)
                        policy_count = len(inline.get("PolicyNames", []))

                        if policy_count > 0:
                            findings.append(
                                Finding(
                                    title=f"User with inline policies: {username}",
                                    severity=Severity.LOW,
                                    service="IAM",
                                    resource=f"user:{username}",
                                    detail=(
                                        f"User has {policy_count} inline policy/policies — "
                                        f"harder to audit and maintain"
                                    ),
                                    remediation=(
                                        f"Migrate inline policies to managed policies for better "
                                        f"visibility, versioning, and reusability."
                                    ),
                                )
                            )
                    except ClientError:
                        continue

        except ClientError:
            pass

        return findings

    def _check_password_policy(self) -> list[Finding]:
        """Check the account password policy for weaknesses.

        Returns:
            Findings for weak password policy settings.
        """
        findings: list[Finding] = []

        try:
            policy = self.iam.get_account_password_policy()
            pp = policy.get("PasswordPolicy", {})

            minimum_length = pp.get("MinimumPasswordLength", 0)
            if minimum_length < 14:
                findings.append(
                    Finding(
                        title="Weak password policy: minimum length too short",
                        severity=Severity.MEDIUM,
                        service="IAM",
                        resource="account-password-policy",
                        detail=f"Minimum password length is {minimum_length} (recommended: 14+)",
                        remediation=(
                            "Update password policy: "
                            "aws iam update-account-password-policy --minimum-password-length 14"
                        ),
                        compliance=["CIS 1.5"],
                    )
                )

            if not pp.get("RequireSymbols", False):
                findings.append(
                    Finding(
                        title="Password policy does not require symbols",
                        severity=Severity.LOW,
                        service="IAM",
                        resource="account-password-policy",
                        detail="Password policy does not enforce symbol requirements",
                        remediation="Enable --require-symbols in the account password policy",
                        compliance=["CIS 1.5"],
                    )
                )

            if not pp.get("RequireNumbers", False):
                findings.append(
                    Finding(
                        title="Password policy does not require numbers",
                        severity=Severity.LOW,
                        service="IAM",
                        resource="account-password-policy",
                        detail="Password policy does not enforce number requirements",
                        remediation="Enable --require-numbers in the account password policy",
                        compliance=["CIS 1.5"],
                    )
                )

            if not pp.get("MaxPasswordAge", 90) <= 90:
                findings.append(
                    Finding(
                        title="Password policy allows long-lived passwords",
                        severity=Severity.LOW,
                        service="IAM",
                        resource="account-password-policy",
                        detail=f"Max password age is {pp.get('MaxPasswordAge', 'N/A')} days (recommended: 90 or less)",
                        remediation="Set --max-password-age to 90 or less",
                        compliance=["CIS 1.6"],
                    )
                )

        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                findings.append(
                    Finding(
                        title="No custom password policy configured",
                        severity=Severity.HIGH,
                        service="IAM",
                        resource="account-password-policy",
                        detail="Account uses default AWS password policy — insufficient for production",
                        remediation=(
                            "Set a custom password policy: "
                            "aws iam update-account-password-policy --minimum-password-length 14 "
                            "--require-symbols --require-numbers --require-uppercase-characters "
                            "--require-lowercase-characters --max-password-age 90"
                        ),
                        compliance=["CIS 1.5"],
                    )
                )

        return findings

    @staticmethod
    def _policy_has_admin_actions(policy_doc: dict) -> bool:
        """Check if a policy document grants admin-level actions.

        Args:
            policy_doc: Decoded IAM policy document.

        Returns:
            True if the policy contains admin-level actions.
        """
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                if action in ADMIN_ACTIONS or action == "*":
                    return True

        return False
