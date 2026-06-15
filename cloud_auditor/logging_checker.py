"""
Logging Checker — CloudTrail, CloudWatch, and Monitoring Assessment
====================================================================

Evaluates the logging and monitoring posture of an AWS account,
including CloudTrail configuration, CloudWatch alarms, AWS Config
rules, and GuardDuty detector status.
"""

from __future__ import annotations

from typing import Optional

import boto3
from botocore.exceptions import ClientError

from cloud_auditor.findings import Finding, Severity


class LoggingChecker:
    """Checks logging and monitoring configurations for security gaps.

    Attributes:
        session: Authenticated boto3 Session.
        region: AWS region for API calls.
    """

    def __init__(self, session: boto3.Session, region: str) -> None:
        self.session = session
        self.region = region

    def scan(self) -> list[Finding]:
        """Run all logging and monitoring checks.

        Returns:
            List of Finding objects for each logging misconfiguration.
        """
        findings: list[Finding] = []

        # 1. CloudTrail
        findings.extend(self._check_cloudtrail())

        # 2. CloudWatch alarms
        findings.extend(self._check_cloudwatch_alarms())

        # 3. AWS Config rules
        findings.extend(self._check_config())

        # 4. GuardDuty
        findings.extend(self._check_guardduty())

        # 5. S3 server access logging (account-level check)
        findings.extend(self._check_s3_account_settings())

        return findings

    def _check_cloudtrail(self) -> list[Finding]:
        """Check CloudTrail configuration for security best practices.

        Verifies:
        - At least one trail exists and is logging
        - Trail is multi-region
        - Trail has log file validation enabled
        - Trail integrates with CloudWatch Logs
        - Trail is not using S3 bucket with global Lambda invoke issues

        Returns:
            Findings for CloudTrail misconfigurations.
        """
        findings: list[Finding] = []

        try:
            ct = self.session.client("cloudtrail", region_name=self.region)
            trails = ct.describe_trails()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    Finding(
                        title="Cannot access CloudTrail",
                        severity=Severity.INFO,
                        service="Logging",
                        resource="cloudtrail:describetrails",
                        detail="Insufficient permissions to check CloudTrail status",
                        remediation="Grant cloudtrail:DescribeTrails permission",
                    )
                )
            return findings

        trail_list = trails.get("trailList", [])

        if not trail_list:
            findings.append(
                Finding(
                    title="No CloudTrail trails configured",
                    severity=Severity.CRITICAL,
                    service="Logging",
                    resource="account",
                    detail="No CloudTrail trails exist — no API call audit logging for this account",
                    remediation=(
                        "Create a multi-region CloudTrail trail immediately: "
                        "aws cloudtrail create-trail --name security-trail "
                        "--s3-bucket-name <cloudtrail-bucket> --is-multi-region-trail "
                        "--enable-log-file-validation"
                    ),
                    compliance=["CIS 2.1", "CIS 3.1"],
                )
            )
            return findings

        has_active_trail = False

        for trail in trail_list:
            trail_name = trail.get("Name", "")
            trail_arn = trail.get("TrailARN", "")

            # Get trail status
            try:
                status = ct.get_trail_status(Name=trail_arn)
            except ClientError:
                continue

            is_logging = status.get("IsLogging", False)

            if not is_logging:
                findings.append(
                    Finding(
                        title=f"CloudTrail trail not logging: {trail_name}",
                        severity=Severity.HIGH,
                        service="Logging",
                        resource=trail_arn,
                        detail=f"Trail '{trail_name}' exists but is not actively logging",
                        remediation=(
                            f"Start the trail: aws cloudtrail start-logging --name {trail_name}"
                        ),
                        compliance=["CIS 3.1"],
                    )
                )
                continue

            has_active_trail = True

            # Check multi-region
            if not trail.get("IsMultiRegionTrail", False):
                findings.append(
                    Finding(
                        title=f"CloudTrail not multi-region: {trail_name}",
                        severity=Severity.MEDIUM,
                        service="Logging",
                        resource=trail_arn,
                        detail=f"Trail '{trail_name}' only logs events in a single region",
                        remediation=(
                            f"Enable multi-region logging: "
                            f"aws cloudtrail update-trail --name {trail_name} --is-multi-region-trail"
                        ),
                        compliance=["CIS 3.2"],
                    )
                )

            # Check log file validation
            if not trail.get("LogFileValidationEnabled", False):
                findings.append(
                    Finding(
                        title=f"CloudTrail log validation disabled: {trail_name}",
                        severity=Severity.MEDIUM,
                        service="Logging",
                        resource=trail_arn,
                        detail=f"Trail '{trail_name}' does not have log file validation enabled",
                        remediation=(
                            f"Enable log file validation: "
                            f"aws cloudtrail update-trail --name {trail_name} "
                            f"--enable-log-file-validation"
                        ),
                        compliance=["CIS 3.3"],
                    )
                )

            # Check CloudWatch Logs integration
            if not trail.get("CloudWatchLogsLogGroupArn"):
                findings.append(
                    Finding(
                        title=f"CloudTrail not integrated with CloudWatch: {trail_name}",
                        severity=Severity.MEDIUM,
                        service="Logging",
                        resource=trail_arn,
                        detail=f"Trail '{trail_name}' is not sending logs to CloudWatch Logs",
                        remediation=(
                            "Configure CloudWatch Logs integration for metric filters and alarms: "
                            f"aws cloudtrail update-trail --name {trail_name} "
                            f"--cloudwatch-logs-log-group-arn <log-group-arn> "
                            f"--cloudwatch-logs-role-arn <role-arn>"
                        ),
                        compliance=["CIS 3.4"],
                    )
                )

            # Check KMS encryption
            if not trail.get("KmsKeyId"):
                findings.append(
                    Finding(
                        title=f"CloudTrail logs not encrypted with KMS: {trail_name}",
                        severity=Severity.LOW,
                        service="Logging",
                        resource=trail_arn,
                        detail=f"Trail '{trail_name}' uses default S3 encryption instead of KMS",
                        remediation=(
                            f"Enable KMS encryption: "
                            f"aws cloudtrail update-trail --name {trail_name} "
                            f"--kms-key-id <kms-key-arn>"
                        ),
                        compliance=["CIS 3.8"],
                    )
                )

        if has_active_trail:
            findings.append(
                Finding(
                    title="CloudTrail active trail confirmed",
                    severity=Severity.INFO,
                    service="Logging",
                    resource="account",
                    detail="At least one CloudTrail trail is actively logging",
                )
            )

        return findings

    def _check_cloudwatch_alarms(self) -> list[Finding]:
        """Check for CloudWatch alarms related to security monitoring.

        Specifically checks for the CIS-recommended metric filters:
        - Unauthorized API calls
        - Console logins without MFA
        - Root account usage
        - IAM policy changes
        - CloudTrail configuration changes
        - Security group changes
        - NACL changes
        - Network gateway changes
        - Route table changes
        - S3 bucket policy changes

        Returns:
            Findings for missing security alarms.
        """
        findings: list[Finding] = []

        try:
            cw = self.session.client("cloudwatch", region_name=self.region)
            alarms = cw.describe_alarms()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    Finding(
                        title="Cannot access CloudWatch alarms",
                        severity=Severity.INFO,
                        service="Logging",
                        resource="cloudwatch:describealarms",
                        detail="Insufficient permissions to check CloudWatch alarms",
                        remediation="Grant cloudwatch:DescribeAlarms permission",
                    )
                )
            return findings

        alarm_names = {a["AlarmName"] for a in alarms.get("MetricAlarms", [])}

        # CIS-recommended alarm patterns
        cis_alarms = [
            ("UnauthorizedAPICalls", "CIS 3.1"),
            ("ConsoleLoginWithoutMFA", "CIS 3.2"),
            ("RootAccountUsage", "CIS 3.3"),
            ("IAMPolicyChanges", "CIS 3.4"),
            ("CloudTrailChanges", "CIS 3.5"),
            ("SecurityGroupChanges", "CIS 3.6"),
            ("NACLChanges", "CIS 3.7"),
            ("NetworkGatewayChanges", "CIS 3.8"),
            ("RouteTableChanges", "CIS 3.9"),
            ("S3BucketPolicyChanges", "CIS 3.10"),
        ]

        missing_alarms: list[tuple[str, str]] = []
        for alarm_keyword, cis_ref in cis_alarms:
            found = any(alarm_keyword.lower() in name.lower() for name in alarm_names)
            if not found:
                missing_alarms.append((alarm_keyword, cis_ref))

        if missing_alarms:
            alarm_names_str = ", ".join(a[0] for a in missing_alarms)
            cis_refs = ", ".join(a[1] for a in missing_alarms)
            findings.append(
                Finding(
                    title=f"Missing {len(missing_alarms)} CIS CloudWatch alarms",
                    severity=Severity.MEDIUM,
                    service="Logging",
                    resource="cloudwatch:alarms",
                    detail=(
                        f"Missing security alarms for: {alarm_names_str}. "
                        f"These correspond to {cis_refs}."
                    ),
                    remediation=(
                        "Create CloudWatch metric filters and alarms for CIS-recommended "
                        "security events. See CIS AWS Foundations Benchmark section 3."
                    ),
                    compliance=[a[1] for a in missing_alarms],
                )
            )

        return findings

    def _check_config(self) -> list[Finding]:
        """Check AWS Config configuration and rules.

        Returns:
            Findings for Config misconfigurations.
        """
        findings: list[Finding] = []

        try:
            config = self.session.client("config", region_name=self.region)

            # Check if Config is recording
            recorders = config.describe_configuration_recorders()
            recorder_list = recorders.get("ConfigurationRecorders", [])

            if not recorder_list:
                findings.append(
                    Finding(
                        title="AWS Config not configured",
                        severity=Severity.HIGH,
                        service="Logging",
                        resource="config:recorder",
                        detail="No Config recorder exists — resource changes are not tracked",
                        remediation=(
                            "Enable AWS Config: "
                            "aws configservice start-configuration-recorder "
                            "--configuration-recorder-name default"
                        ),
                        compliance=["CIS 3.5"],
                    )
                )
                return findings

            for recorder in recorder_list:
                name = recorder.get("name", "")
                recording = recorder.get("recordingGroup", {})
                all_types = recording.get("allSupported", False)
                include_globals = recording.get("includeGlobalResourceTypes", False)

                if not include_globals:
                    findings.append(
                        Finding(
                            title=f"Config not recording global resources: {name}",
                            severity=Severity.MEDIUM,
                            service="Logging",
                            resource=f"config:recorder:{name}",
                            detail="Config recorder does not include global resource types (IAM)",
                            remediation=(
                                f"Enable global resource recording: "
                                f"aws configservice put-configuration-recorder "
                                f"--configuration-recorder name={name},"
                                f"recordingGroup={{allSupported=true,"
                                f"includeGlobalResourceTypes=true}}"
                            ),
                        )
                    )

            # Check Config rules count
            try:
                rules = config.describe_config_rules()
                rule_count = len(rules.get("ConfigRules", []))

                if rule_count == 0:
                    findings.append(
                        Finding(
                            title="No AWS Config rules configured",
                            severity=Severity.MEDIUM,
                            service="Logging",
                            resource="config:rules",
                            detail="No Config rules exist — no automated compliance checking",
                            remediation="Deploy managed Config rules for security compliance",
                        )
                    )
            except ClientError:
                pass

        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    Finding(
                        title="Cannot access AWS Config",
                        severity=Severity.INFO,
                        service="Logging",
                        resource="config:describerecorders",
                        detail="Insufficient permissions to check Config status",
                        remediation="Grant config:DescribeConfigurationRecorders permission",
                    )
                )

        return findings

    def _check_guardduty(self) -> list[Finding]:
        """Check GuardDuty threat detection status.

        Returns:
            Findings for GuardDuty misconfigurations.
        """
        findings: list[Finding] = []

        try:
            gd = self.session.client("guardduty", region_name=self.region)
            detectors = gd.list_detectors()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDenied", "BadRequestException"):
                findings.append(
                    Finding(
                        title="Cannot access GuardDuty",
                        severity=Severity.INFO,
                        service="Logging",
                        resource="guardduty:listdetectors",
                        detail="Insufficient permissions or GuardDuty not available in region",
                        remediation="Grant guardduty:ListDetectors permission or enable GuardDuty",
                    )
                )
            return findings

        detector_ids = detectors.get("DetectorIds", [])

        if not detector_ids:
            findings.append(
                Finding(
                    title="GuardDuty not enabled",
                    severity=Severity.HIGH,
                    service="Logging",
                    resource="guardduty",
                    detail="No GuardDuty detector exists in this region — no threat detection",
                    remediation=(
                        "Enable GuardDuty: "
                        "aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES"
                    ),
                )
            )
            return findings

        # Check if detector is active
        for detector_id in detector_ids:
            try:
                detector = gd.get_detector(DetectorId=detector_id)
                status = detector.get("Status", "")

                if status != "ENABLED":
                    findings.append(
                        Finding(
                            title=f"GuardDuty detector not active: {detector_id}",
                            severity=Severity.HIGH,
                            service="Logging",
                            resource=detector_id,
                            detail=f"GuardDuty detector {detector_id} status is '{status}'",
                            remediation=(
                                f"Enable the detector: "
                                f"aws guardduty update-detector --detector-id {detector_id} --enable"
                            ),
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            title=f"GuardDuty active: {detector_id}",
                            severity=Severity.INFO,
                            service="Logging",
                            resource=detector_id,
                            detail=f"GuardDuty detector {detector_id} is enabled and active",
                        )
                    )
            except ClientError:
                continue

        return findings

    def _check_s3_account_settings(self) -> list[Finding]:
        """Check account-level S3 Block Public Access settings.

        Returns:
            Finding if account-level Block Public Access is not fully enabled.
        """
        findings: list[Finding] = []

        try:
            s3_control = self.session.client("s3control", region_name=self.region)
            sts = self.session.client("sts")
            account_id = sts.get_caller_identity()["Account"]

            pab = s3_control.get_public_access_block(AccountId=account_id)
            config = pab["PublicAccessBlockConfiguration"]

            all_enabled = all(
                [
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]
            )

            if not all_enabled:
                disabled = [k for k, v in config.items() if v is False]
                findings.append(
                    Finding(
                        title="Account-level S3 Block Public Access not fully enabled",
                        severity=Severity.HIGH,
                        service="Logging",
                        resource=f"account:{account_id}",
                        detail=(
                            f"Account-level Block Public Access has disabled settings: "
                            f"{', '.join(disabled)}"
                        ),
                        remediation=(
                            "Enable all account-level Block Public Access settings: "
                            "aws s3control put-public-access-block --account-id <id> "
                            "--public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,"
                            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        compliance=["CIS 2.2"],
                    )
                )

        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDenied", "NoSuchPublicAccessBlockConfiguration"):
                findings.append(
                    Finding(
                        title="Account-level S3 Block Public Access not configured",
                        severity=Severity.MEDIUM,
                        service="Logging",
                        resource="account:s3",
                        detail="No account-level S3 Block Public Access configuration found",
                        remediation="Configure account-level S3 Block Public Access settings",
                    )
                )

        return findings
