"""
EC2 Auditor — Instance and Volume Security Assessment
======================================================

Audits EC2 instances for security misconfigurations including
public instances, open security groups, missing IAM roles,
unencrypted EBS volumes, and outdated instance types.
"""

from __future__ import annotations

from typing import Optional

import boto3
from botocore.exceptions import ClientError

from cloud_auditor.findings import Finding, Severity


# Ports that should NEVER be open to 0.0.0.0/0
CRITICAL_OPEN_PORTS = {22, 3389}

# Ports that are sensitive when open to the world
SENSITIVE_OPEN_PORTS = {
    21,    # FTP
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    110,   # POP3
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    445,   # SMB
    1433,  # MSSQL
    1434,  # MSSQL Browser
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # HTTP Alt
    8443,  # HTTPS Alt
    9200,  # Elasticsearch
    27017, # MongoDB
}

# Deprecated/outdated instance families
OUTDATED_FAMILIES = {
    "t1", "m1", "m2", "m3", "c1", "c3", "cc2", "cr1",
    "hi1", "hs1", "i2", "r3", "g2", "cg1",
}


class EC2Auditor:
    """Audits EC2 instances, security groups, and EBS volumes.

    Attributes:
        session: Authenticated boto3 Session.
        region: AWS region for API calls.
    """

    def __init__(self, session: boto3.Session, region: str) -> None:
        self.session = session
        self.region = region
        self.ec2 = session.client("ec2", region_name=region)

    def scan(self) -> list[Finding]:
        """Run all EC2 security checks.

        Returns:
            List of Finding objects for each EC2 misconfiguration.
        """
        findings: list[Finding] = []

        # 1. Check security groups for open ports
        findings.extend(self._check_security_groups())

        # 2. Check EC2 instances for security issues
        findings.extend(self._check_instances())

        # 3. Check EBS volumes for encryption
        findings.extend(self._check_ebs_encryption())

        return findings

    def _check_security_groups(self) -> list[Finding]:
        """Check security groups for overly permissive inbound rules.

        Specifically flags:
        - SSH (22) open to 0.0.0.0/0
        - RDP (3389) open to 0.0.0.0/0
        - Any sensitive port open to the world
        - All traffic (0-65535) open to the world

        Returns:
            Findings for each security group with dangerous rules.
        """
        findings: list[Finding] = []

        try:
            paginator = self.ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", "")
                    vpc_id = sg.get("VpcId", "EC2-Classic")

                    for rule in sg.get("IpPermissions", []):
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        ip_protocol = rule.get("IpProtocol", "")

                        for ip_range in rule.get("IpRanges", []):
                            cidr = ip_range.get("CidrIp", "")

                            if cidr != "0.0.0.0/0":
                                continue

                            # All traffic open
                            if ip_protocol == "-1":
                                findings.append(
                                    Finding(
                                        title=f"All traffic open to world: {sg_name}",
                                        severity=Severity.CRITICAL,
                                        service="EC2",
                                        resource=sg_id,
                                        detail=(
                                            f"Security group '{sg_name}' ({sg_id}) allows ALL TRAFFIC "
                                            f"from 0.0.0.0/0. VPC: {vpc_id}"
                                        ),
                                        remediation=(
                                            f"Remove the all-traffic inbound rule from '{sg_name}'. "
                                            f"Restrict to specific IPs and ports."
                                        ),
                                        compliance=["CIS 4.1", "CIS 4.2"],
                                        region=self.region,
                                    )
                                )
                                continue

                            # Check specific ports
                            if from_port is not None and to_port is not None:
                                port_range = range(from_port, to_port + 1)

                                for port in port_range:
                                    if port in CRITICAL_OPEN_PORTS:
                                        port_name = "SSH" if port == 22 else "RDP"
                                        findings.append(
                                            Finding(
                                                title=f"{port_name} ({port}) open to world: {sg_name}",
                                                severity=Severity.CRITICAL,
                                                service="EC2",
                                                resource=sg_id,
                                                detail=(
                                                    f"Security group '{sg_name}' ({sg_id}) allows "
                                                    f"{port_name} (port {port}) from 0.0.0.0/0. "
                                                    f"VPC: {vpc_id}"
                                                ),
                                                remediation=(
                                                    f"Restrict port {port} to specific IP ranges. "
                                                    f"Use a bastion host or VPN for SSH/RDP access."
                                                ),
                                                compliance=["CIS 4.1", "CIS 4.2"],
                                                region=self.region,
                                            )
                                        )

                                    elif port in SENSITIVE_OPEN_PORTS:
                                        findings.append(
                                            Finding(
                                                title=f"Sensitive port {port} open to world: {sg_name}",
                                                severity=Severity.HIGH,
                                                service="EC2",
                                                resource=sg_id,
                                                detail=(
                                                    f"Security group '{sg_name}' ({sg_id}) allows "
                                                    f"port {port} from 0.0.0.0/0. VPC: {vpc_id}"
                                                ),
                                                remediation=(
                                                    f"Restrict port {port} access to specific IP ranges "
                                                    f"or remove the rule if unused."
                                                ),
                                                compliance=["CIS 4.2"],
                                                region=self.region,
                                            )
                                        )

        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    Finding(
                        title="Cannot describe security groups",
                        severity=Severity.INFO,
                        service="EC2",
                        resource="ec2:describesecuritygroups",
                        detail="Insufficient permissions to enumerate security groups",
                        remediation="Grant ec2:DescribeSecurityGroups permission",
                    )
                )

        return findings

    def _check_instances(self) -> list[Finding]:
        """Check EC2 instances for security issues.

        Checks for:
        - Public IP addresses (potential exposure)
        - Missing IAM instance profiles
        - Outdated instance types

        Returns:
            Findings for each instance-level misconfiguration.
        """
        findings: list[Finding] = []

        try:
            paginator = self.ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_id = instance.get("InstanceId", "")
                        state = instance.get("State", {}).get("Name", "")

                        # Skip terminated instances
                        if state == "terminated":
                            continue

                        instance_type = instance.get("InstanceType", "")
                        instance_family = instance_type.split(".")[0] if "." in instance_type else ""

                        # Check for public IP
                        public_ip = instance.get("PublicIpAddress")
                        if public_ip and state == "running":
                            name = self._get_instance_name(instance)
                            findings.append(
                                Finding(
                                    title=f"EC2 instance with public IP: {name or instance_id}",
                                    severity=Severity.MEDIUM,
                                    service="EC2",
                                    resource=instance_id,
                                    detail=(
                                        f"Instance {instance_id} ({instance_type}) has public IP "
                                        f"{public_ip}. State: {state}."
                                    ),
                                    remediation=(
                                        "Review if the public IP is necessary. "
                                        "Consider placing behind a load balancer or using a VPN."
                                    ),
                                    region=self.region,
                                )
                            )

                        # Check for missing IAM role
                        iam_profile = instance.get("IamInstanceProfile")
                        if not iam_profile and state == "running":
                            findings.append(
                                Finding(
                                    title=f"EC2 instance without IAM role: {instance_id}",
                                    severity=Severity.MEDIUM,
                                    service="EC2",
                                    resource=instance_id,
                                    detail=(
                                        f"Instance {instance_id} has no IAM instance profile — "
                                        f"applications may embed credentials instead"
                                    ),
                                    remediation=(
                                        "Attach an IAM instance profile to grant temporary credentials: "
                                        "aws ec2 associate-iam-instance-profile --instance-id "
                                        f"{instance_id} --iam-instance-profile Name=<profile>"
                                    ),
                                    region=self.region,
                                )
                            )

                        # Check for outdated instance type
                        if instance_family in OUTDATED_FAMILIES:
                            findings.append(
                                Finding(
                                    title=f"Outdated EC2 instance type: {instance_id}",
                                    severity=Severity.LOW,
                                    service="EC2",
                                    resource=instance_id,
                                    detail=(
                                        f"Instance uses {instance_type} — the {instance_family} family "
                                        f"is deprecated. Consider upgrading to current generation."
                                    ),
                                    remediation=(
                                        f"Migrate to a current-generation instance type "
                                        f"(e.g., t3, m5, c5, r5) for better performance and security."
                                    ),
                                    region=self.region,
                                )
                            )

        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    Finding(
                        title="Cannot describe EC2 instances",
                        severity=Severity.INFO,
                        service="EC2",
                        resource="ec2:describeinstances",
                        detail="Insufficient permissions to enumerate EC2 instances",
                        remediation="Grant ec2:DescribeInstances permission",
                    )
                )

        return findings

    def _check_ebs_encryption(self) -> list[Finding]:
        """Check for unencrypted EBS volumes.

        Returns:
            Findings for each unencrypted volume.
        """
        findings: list[Finding] = []

        try:
            paginator = self.ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    volume_id = volume.get("VolumeId", "")
                    encrypted = volume.get("Encrypted", False)
                    state = volume.get("State", "")

                    if not encrypted and state == "in-use":
                        attachments = volume.get("Attachments", [])
                        attached_to = ", ".join(
                            a.get("InstanceId", "unknown") for a in attachments
                        ) or "unattached"

                        findings.append(
                            Finding(
                                title=f"Unencrypted EBS volume: {volume_id}",
                                severity=Severity.HIGH,
                                service="EC2",
                                resource=volume_id,
                                detail=(
                                    f"Volume {volume_id} is not encrypted. "
                                    f"Size: {volume.get('Size', '?')}GB. "
                                    f"Attached to: {attached_to}"
                                ),
                                remediation=(
                                    "Create an encrypted snapshot of this volume, then create a new "
                                    "encrypted volume from the snapshot. Alternatively, enable EBS "
                                    "encryption by default for new volumes."
                                ),
                                compliance=["CIS 4.3"],
                                region=self.region,
                            )
                        )

        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    Finding(
                        title="Cannot describe EBS volumes",
                        severity=Severity.INFO,
                        service="EC2",
                        resource="ec2:describevolumes",
                        detail="Insufficient permissions to enumerate EBS volumes",
                        remediation="Grant ec2:DescribeVolumes permission",
                    )
                )

        return findings

    @staticmethod
    def _get_instance_name(instance: dict) -> str:
        """Extract the Name tag from an EC2 instance.

        Args:
            instance: EC2 instance dictionary from describe_instances.

        Returns:
            The Name tag value, or empty string if not set.
        """
        for tag in instance.get("Tags", []):
            if tag.get("Key") == "Name":
                return tag.get("Value", "")
        return ""
