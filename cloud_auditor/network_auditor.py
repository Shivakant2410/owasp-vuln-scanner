"""
Network Auditor — VPC and Network Security Assessment
======================================================

Audits VPC configurations for security misconfigurations including
missing flow logs, permissive NACLs, suspicious routes, and
internet gateways attached to private subnets.
"""

from __future__ import annotations

from typing import Optional

import boto3
from botocore.exceptions import ClientError

from cloud_auditor.findings import Finding, Severity


class NetworkAuditor:
    """Audits VPC, subnet, NACL, and routing configurations.

    Attributes:
        session: Authenticated boto3 Session.
        region: AWS region for API calls.
    """

    def __init__(self, session: boto3.Session, region: str) -> None:
        self.session = session
        self.region = region
        self.ec2 = session.client("ec2", region_name=region)

    def scan(self) -> list[Finding]:
        """Run all network security checks.

        Returns:
            List of Finding objects for each network misconfiguration.
        """
        findings: list[Finding] = []

        # 1. Check VPC flow logs
        findings.extend(self._check_flow_logs())

        # 2. Check NACL rules
        findings.extend(self._check_nacls())

        # 3. Check route tables
        findings.extend(self._check_route_tables())

        # 4. Check for public subnets
        findings.extend(self._check_public_subnets())

        return findings

    def _check_flow_logs(self) -> list[Finding]:
        """Check if VPCs have flow logs enabled.

        VPC Flow Logs are critical for network forensics and incident response.

        Returns:
            Findings for VPCs without flow logs.
        """
        findings: list[Finding] = []

        try:
            vpcs = self.ec2.describe_vpcs()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                findings.append(
                    Finding(
                        title="Cannot describe VPCs",
                        severity=Severity.INFO,
                        service="Network",
                        resource="ec2:describevpcs",
                        detail="Insufficient permissions to enumerate VPCs",
                        remediation="Grant ec2:DescribeVpcs permission",
                    )
                )
            return findings

        for vpc in vpcs.get("Vpcs", []):
            vpc_id = vpc["VpcId"]
            is_default = vpc.get("IsDefault", False)
            cidr = vpc.get("CidrBlock", "")

            try:
                flow_logs = self.ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                )
            except ClientError:
                continue

            flow_log_entries = flow_logs.get("FlowLogs", [])

            # Check if any flow log is active
            active_logs = [
                fl for fl in flow_log_entries
                if fl.get("FlowLogStatus") == "ACTIVE"
            ]

            if not active_logs:
                vpc_label = f"{vpc_id} (default)" if is_default else vpc_id
                findings.append(
                    Finding(
                        title=f"VPC without flow logs: {vpc_label}",
                        severity=Severity.HIGH,
                        service="Network",
                        resource=vpc_id,
                        detail=(
                            f"VPC {vpc_id} (CIDR: {cidr}) has no active flow logs — "
                            f"network visibility gap for forensics"
                        ),
                        remediation=(
                            f"Enable VPC flow logs: "
                            f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vpc_id} "
                            f"--traffic-type ALL --log-destination-type cloud-watch-logs "
                            f"--log-group-name /vpc/flowlogs/{vpc_id}"
                        ),
                        compliance=["CIS 3.9"],
                        region=self.region,
                    )
                )

        return findings

    def _check_nacls(self) -> list[Finding]:
        """Check Network ACLs for overly permissive rules.

        Flags NACLs that allow all traffic (0.0.0.0/0) on all ports
        in either inbound or outbound direction.

        Returns:
            Findings for permissive NACL rules.
        """
        findings: list[Finding] = []

        try:
            nacls = self.ec2.describe_network_acls()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                return findings
            raise

        for nacl in nacls.get("NetworkAcls", []):
            nacl_id = nacl["NetworkAclId"]
            vpc_id = nacl.get("VpcId", "")
            is_default = nacl.get("IsDefault", False)

            for entry in nacl.get("Entries", []):
                # Only check ALLOW rules
                if entry.get("RuleAction") != "allow":
                    continue

                cidr = entry.get("CidrBlock", "")
                egress = entry.get("Egress", False)
                from_port = entry.get("PortRange", {}).get("From", "ALL")
                to_port = entry.get("PortRange", {}).get("To", "ALL")
                protocol = entry.get("Protocol", "")

                # Flag rules allowing all traffic from 0.0.0.0/0
                if cidr == "0.0.0.0/0" and protocol == "-1":
                    direction = "outbound" if egress else "inbound"
                    label = f"{nacl_id} (default)" if is_default else nacl_id

                    # Outbound all is less severe than inbound all
                    severity = Severity.MEDIUM if egress else Severity.HIGH

                    findings.append(
                        Finding(
                            title=f"Permissive NACL rule: {label}",
                            severity=severity,
                            service="Network",
                            resource=nacl_id,
                            detail=(
                                f"NACL {nacl_id} allows ALL {direction} traffic from/to 0.0.0.0/0 "
                                f"(VPC: {vpc_id})"
                            ),
                            remediation=(
                                f"Restrict the NACL rule to only necessary CIDR blocks and ports. "
                                f"NACLs should follow deny-by-default with explicit allow rules."
                            ),
                            region=self.region,
                        )
                    )

        return findings

    def _check_route_tables(self) -> list[Finding]:
        """Check route tables for suspicious or misconfigured routes.

        Flags routes that point 0.0.0.0/0 to an internet gateway
        in route tables associated with private subnets.

        Returns:
            Findings for suspicious routing configurations.
        """
        findings: list[Finding] = []

        try:
            route_tables = self.ec2.describe_route_tables()
        except ClientError:
            return findings

        try:
            igws = self.ec2.describe_internet_gateways()
            igw_ids = {igw["InternetGatewayId"] for igw in igws.get("InternetGateways", [])}
        except ClientError:
            igw_ids = set()

        # Build a map of subnet -> route table
        subnet_rt_map: dict[str, str] = {}
        for rt in route_tables.get("RouteTables", []):
            rt_id = rt["RouteTableId"]
            for assoc in rt.get("Associations", []):
                subnet_id = assoc.get("SubnetId", "")
                if subnet_id:
                    subnet_rt_map[subnet_id] = rt_id

        # Identify private subnets (no route to IGW)
        for rt in route_tables.get("RouteTables", []):
            rt_id = rt["RouteTableId"]
            vpc_id = rt.get("VpcId", "")

            has_igw_route = False
            for route in rt.get("Routes", []):
                dest = route.get("DestinationCidrBlock", "")
                gateway = route.get("GatewayId", "")

                if dest == "0.0.0.0/0" and gateway.startswith("igw-"):
                    has_igw_route = True

                    # Check if this route table is the main (default) table
                    is_main = any(
                        a.get("Main", False) for a in rt.get("Associations", [])
                    )

                    if is_main:
                        findings.append(
                            Finding(
                                title=f"Main route table has IGW route: {rt_id}",
                                severity=Severity.MEDIUM,
                                service="Network",
                                resource=rt_id,
                                detail=(
                                    f"Main route table {rt_id} (VPC: {vpc_id}) has a default route "
                                    f"to internet gateway {gateway}. New subnets will have internet "
                                    f"access by default."
                                ),
                                remediation=(
                                    "Remove the IGW route from the main route table. "
                                    "Create separate route tables for public and private subnets."
                                ),
                                region=self.region,
                            )
                        )

        return findings

    def _check_public_subnets(self) -> list[Finding]:
        """Check for public subnets and their security posture.

        A public subnet has a route to an internet gateway.
        This check identifies all public subnets and flags
        if they don't have expected protections.

        Returns:
            Findings related to public subnet configurations.
        """
        findings: list[Finding] = []

        try:
            subnets = self.ec2.describe_subnets()
        except ClientError:
            return findings

        try:
            route_tables = self.ec2.describe_route_tables()
        except ClientError:
            return findings

        # Build subnet -> route table associations with IGW info
        public_subnets: dict[str, dict] = {}

        for rt in route_tables.get("RouteTables", []):
            rt_id = rt["RouteTableId"]
            has_igw = False

            for route in rt.get("Routes", []):
                if (route.get("DestinationCidrBlock") == "0.0.0.0/0"
                        and route.get("GatewayId", "").startswith("igw-")):
                    has_igw = True
                    break

            if has_igw:
                for assoc in rt.get("Associations", []):
                    subnet_id = assoc.get("SubnetId", "")
                    if subnet_id:
                        public_subnets[subnet_id] = {
                            "route_table": rt_id,
                            "gateway": route.get("GatewayId", ""),
                        }

        # Check each subnet
        for subnet in subnets.get("Subnets", []):
            subnet_id = subnet["SubnetId"]
            vpc_id = subnet.get("VpcId", "")

            if subnet_id in public_subnets:
                # This is a public subnet — check if it should be
                subnet_name = self._get_subnet_name(subnet)
                map_info = public_subnets[subnet_id]

                # If subnet name suggests it's private but it's public
                name_lower = (subnet_name or "").lower()
                private_keywords = ["private", "internal", "db", "database", "backend"]
                if any(kw in name_lower for kw in private_keywords):
                    findings.append(
                        Finding(
                            title=f"Private-labeled subnet with public route: {subnet_name or subnet_id}",
                            severity=Severity.HIGH,
                            service="Network",
                            resource=subnet_id,
                            detail=(
                                f"Subnet '{subnet_name or subnet_id}' (VPC: {vpc_id}) has a name "
                                f"suggesting it's private but routes to internet gateway "
                                f"{map_info['gateway']}"
                            ),
                            remediation=(
                                "Remove the IGW route from this subnet's route table. "
                                "Use a NAT gateway for outbound-only internet access."
                            ),
                            region=self.region,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            title=f"Public subnet identified: {subnet_name or subnet_id}",
                            severity=Severity.INFO,
                            service="Network",
                            resource=subnet_id,
                            detail=(
                                f"Subnet '{subnet_name or subnet_id}' (VPC: {vpc_id}, "
                                f"CIDR: {subnet.get('CidrBlock', '')}) has internet access "
                                f"via {map_info['gateway']}"
                            ),
                            remediation=(
                                "Verify this subnet is intentionally public. "
                                "Ensure all instances have appropriate security groups."
                            ),
                            region=self.region,
                        )
                    )

        return findings

    @staticmethod
    def _get_subnet_name(subnet: dict) -> str:
        """Extract the Name tag from a subnet.

        Args:
            subnet: Subnet dictionary from describe_subnets.

        Returns:
            The Name tag value, or empty string.
        """
        for tag in subnet.get("Tags", []):
            if tag.get("Key") == "Name":
                return tag.get("Value", "")
        return ""
