"""
External Recon — Credential-less Cloud Security Reconnaissance
==============================================================

Performs external reconnaissance against a target domain to discover
cloud-exposed resources without requiring any AWS/cloud credentials.
This demonstrates offensive security capability for cloud attack
surface assessment.

Checks include:
- Exposed S3 buckets via DNS resolution
- Azure Blob storage exposure
- GCP Storage bucket exposure
- Cloud metadata endpoint exposure (SSRF vectors)
- Exposed .env and .git directories
- Cloud-specific HTTP response headers
"""

from __future__ import annotations

import json
import socket
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, Timeout

from cloud_auditor.findings import Finding, Severity


# Common S3 bucket name patterns derived from domain
S3_BUCKET_FORMATS = [
    "{domain}",
    "{domain}-backup",
    "{domain}-backups",
    "{domain}-data",
    "{domain}-media",
    "{domain}-static",
    "{domain}-assets",
    "{domain}-uploads",
    "{domain}-files",
    "{domain}-logs",
    "{domain}-www",
    "www-{domain}",
    "{domain}-prod",
    "{domain}-staging",
    "{domain}-dev",
    "{domain}-test",
    "{domain}-internal",
    "{domain}-deploy",
    "{domain}-terraform",
    "{domain}-config",
    "{domain}-secrets",
    "{domain}-private",
    "{domain}-public",
    "{domain}-reports",
    "{domain}-downloads",
    "{domain}-documents",
    "{domain}-screenshots",
    "{domain}-invoices",
    "{domain}-backoffice",
    "{domain}-admin",
]

# Azure Blob container name patterns
AZURE_BLOB_FORMATS = [
    "{domain}",
    "{domain}data",
    "{domain}backup",
    "{domain}media",
    "{domain}files",
    "{domain}logs",
    "{domain}static",
    "{domain}assets",
]

# GCP Storage bucket name patterns (must be globally unique, dots replaced with hyphens)
GCP_STORAGE_FORMATS = [
    "{domain}",
    "{domain}-data",
    "{domain}-backup",
    "{domain}-media",
    "{domain}-static",
    "{domain}-uploads",
    "www.{domain}",
    "{domain}.appspot.com",
]

# Sensitive file paths to check on the target domain
SENSITIVE_PATHS = [
    "/.env",
    "/.env.production",
    "/.env.local",
    "/.env.backup",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.htaccess",
    "/.htpasswd",
    "/wp-config.php",
    "/config.php",
    "/config.json",
    "/config.yml",
    "/configuration.php",
    "/database.yml",
    "/credentials.json",
    "/serviceAccountKey.json",
    "/package.json",
    "/composer.json",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.DS_Store",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/.well-known/security.txt",
]

# Cloud-specific HTTP response headers
CLOUD_HEADERS = {
    "x-amz-request-id": "AWS S3",
    "x-amz-id-2": "AWS S3",
    "x-amz-bucket-region": "AWS S3 (region revealed)",
    "x-amz-version-id": "AWS S3",
    "x-azure-ref": "Azure",
    "x-azure-request-id": "Azure",
    "x-ms-request-id": "Azure Storage",
    "x-ms-version": "Azure Storage",
    "x-guploader-uploadid": "GCP Storage",
    "x-goog-storage-class": "GCP Storage",
    "x-goog-metageneration": "GCP Storage",
    "x-gcloud-trace": "GCP",
    "x-cloud-trace-context": "GCP",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront (PoP revealed)",
    "x-cache": "CloudFront Cache",
    "x-fastly-request-id": "Fastly CDN",
    "x-served-by": "Fastly CDN",
    "server": "Server header (may reveal cloud backend)",
}

# Request timeout for external checks
REQUEST_TIMEOUT = 8


class ExternalRecon:
    """Performs external cloud reconnaissance without cloud credentials.

    This scanner uses DNS resolution, HTTP requests, and header analysis
    to discover cloud-exposed resources for a given domain.

    Attributes:
        domain: Target domain to assess.
        findings: Collected security findings.
    """

    def __init__(self, domain: str) -> None:
        """Initialize the external reconnaissance scanner.

        Args:
            domain: Target domain (e.g., 'example.com').
        """
        self.domain = domain.strip().lower()
        # Remove protocol prefix if present
        if self.domain.startswith("http://"):
            self.domain = self.domain[7:]
        elif self.domain.startswith("https://"):
            self.domain = self.domain[8:]
        self.domain = self.domain.split("/")[0]  # Remove any path

        self.findings: list[Finding] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CloudSecurityAuditor/1.2.0 (Security Assessment)",
        })

    def scan(self) -> list[Finding]:
        """Run all external reconnaissance checks.

        Returns:
            List of Finding objects for each discovered exposure.
        """
        print(f"\n\033[1m[*] Starting external cloud recon for: {self.domain}\033[0m\n")

        # 1. Check for exposed S3 buckets
        self._check_s3_buckets()

        # 2. Check for exposed Azure Blob storage
        self._check_azure_blobs()

        # 3. Check for exposed GCP Storage
        self._check_gcp_storage()

        # 4. Check cloud metadata endpoint exposure
        self._check_metadata_endpoints()

        # 5. Check for sensitive file exposure on the domain
        self._check_sensitive_paths()

        # 6. Analyze cloud-specific HTTP headers
        self._check_cloud_headers()

        # 7. Check DNS records for cloud indicators
        self._check_dns_cloud_records()

        return self.findings

    def _check_s3_buckets(self) -> None:
        """Check for exposed S3 buckets by trying common naming patterns.

        Uses DNS resolution and HTTP requests to determine if a bucket
        exists and is publicly accessible.
        """
        print("  \033[36m→\033[0m Checking S3 bucket exposure...")

        base_domain = self.domain.replace(".", "-")
        bucket_names = [fmt.format(domain=base_domain) for fmt in S3_BUCKET_FORMATS]

        # Also try the domain as-is (with dots)
        bucket_names.append(self.domain.replace(".", ""))

        for bucket_name in bucket_names:
            # DNS-based check: does the S3 bucket resolve?
            s3_hostname = f"{bucket_name}.s3.amazonaws.com"

            try:
                socket.getaddrinfo(s3_hostname, 443)
                # DNS resolves — bucket exists, check accessibility
                self._check_s3_bucket_access(bucket_name)
            except socket.gaierror:
                # DNS doesn't resolve — bucket likely doesn't exist
                continue

    def _check_s3_bucket_access(self, bucket_name: str) -> None:
        """Check if an S3 bucket is publicly accessible.

        Args:
            bucket_name: Name of the S3 bucket to test.
        """
        url = f"https://{bucket_name}.s3.amazonaws.com/"

        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)

            if response.status_code == 200:
                # Publicly accessible — check contents
                content_length = len(response.text)
                has_listable_content = "<Contents>" in response.text or "<Key>" in response.text

                severity = Severity.CRITICAL if has_listable_content else Severity.HIGH

                detail = f"Bucket '{bucket_name}' is publicly accessible via HTTP."
                if has_listable_content:
                    detail += " Bucket contents are LISTABLE — file keys are exposed."

                self.findings.append(
                    Finding(
                        title=f"Exposed S3 bucket: {bucket_name}",
                        severity=severity,
                        service="S3-Recon",
                        resource=bucket_name,
                        detail=detail,
                        remediation=(
                            "Enable S3 Block Public Access on this bucket. "
                            "Review bucket ACL and policy for public grants. "
                            "Rotate any exposed credentials immediately."
                        ),
                    )
                )

            elif response.status_code == 403:
                # Exists but not publicly readable — still informational
                self.findings.append(
                    Finding(
                        title=f"S3 bucket exists (access denied): {bucket_name}",
                        severity=Severity.INFO,
                        service="S3-Recon",
                        resource=bucket_name,
                        detail=(
                            f"Bucket '{bucket_name}' exists but returns 403 — "
                            f"not publicly readable, but its existence is confirmed"
                        ),
                        remediation=(
                            "Consider enabling S3 Block Public Access and "
                            "denying s3:ListBucket for anonymous principals."
                        ),
                    )
                )

        except (Timeout, RequestException):
            pass

    def _check_azure_blobs(self) -> None:
        """Check for exposed Azure Blob Storage containers.

        Azure Blob URLs follow the pattern:
        https://<account>.blob.core.windows.net/<container>
        """
        print("  \033[36m→\033[0m Checking Azure Blob exposure...")

        account_name = self.domain.replace(".", "").replace("-", "")
        container_names = [fmt.format(domain=self.domain.replace(".", "")) for fmt in AZURE_BLOB_FORMATS]

        for container_name in container_names:
            url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"

            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)

                if response.status_code == 200:
                    has_blobs = "<Blob>" in response.text or "<Name>" in response.text

                    severity = Severity.CRITICAL if has_blobs else Severity.HIGH

                    self.findings.append(
                        Finding(
                            title=f"Exposed Azure Blob container: {container_name}",
                            severity=severity,
                            service="Azure-Recon",
                            resource=f"{account_name}/{container_name}",
                            detail=(
                                f"Azure Blob container '{container_name}' in account '{account_name}' "
                                f"is publicly accessible. {'Files are LISTABLE.' if has_blobs else ''}"
                            ),
                            remediation="Set container access level to 'Private' in Azure Portal or CLI",
                        )
                    )

            except (Timeout, RequestException):
                pass

    def _check_gcp_storage(self) -> None:
        """Check for exposed GCP Storage buckets.

        GCP Storage URLs follow the pattern:
        https://storage.googleapis.com/<bucket>
        """
        print("  \033[36m→\033[0m Checking GCP Storage exposure...")

        base_name = self.domain.replace(".", "-")
        bucket_names = [fmt.format(domain=base_name) for fmt in GCP_STORAGE_FORMATS]

        for bucket_name in bucket_names:
            url = f"https://storage.googleapis.com/{bucket_name}/"

            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)

                if response.status_code == 200:
                    has_objects = "<Contents>" in response.text or "<Key>" in response.text

                    severity = Severity.CRITICAL if has_objects else Severity.HIGH

                    self.findings.append(
                        Finding(
                            title=f"Exposed GCP Storage bucket: {bucket_name}",
                            severity=severity,
                            service="GCP-Recon",
                            resource=bucket_name,
                            detail=(
                                f"GCP Storage bucket '{bucket_name}' is publicly accessible. "
                                f"{'Objects are LISTABLE.' if has_objects else ''}"
                            ),
                            remediation="Set bucket IAM policy to deny allUsers access",
                        )
                    )

            except (Timeout, RequestException):
                pass

    def _check_metadata_endpoints(self) -> None:
        """Check if cloud instance metadata endpoints are accessible.

        This simulates an SSRF attack vector. The 169.254.169.254
        endpoint should only be accessible from within a cloud instance,
        but misconfigured proxies or applications may expose it.
        """
        print("  \033[36m→\033[0m Checking cloud metadata endpoint exposure...")

        metadata_endpoints = [
            ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/"),
            ("AWS IMDSv2", "http://169.254.169.254/latest/meta-data/", {"X-aws-ec2-metadata-token": "test"}),
            ("Azure IMDS", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}),
            ("GCP IMDS", "http://metadata.google.internal/computeMetadata/v1/", {"Metadata-Flavor": "Google"}),
            ("DigitalOcean IMDS", "http://169.254.169.254/metadata/v1/"),
        ]

        for name, url, *extra_headers in metadata_endpoints:
            headers = dict(self.session.headers)
            if extra_headers:
                headers.update(extra_headers[0])

            try:
                response = self.session.get(
                    url,
                    headers=headers,
                    timeout=5,
                    allow_redirects=False,
                )

                if response.status_code == 200:
                    self.findings.append(
                        Finding(
                            title=f"Cloud metadata endpoint accessible: {name}",
                            severity=Severity.CRITICAL,
                            service="SSRF-Recon",
                            resource="169.254.169.254",
                            detail=(
                                f"The {name} metadata endpoint returned a 200 response — "
                                f"potential SSRF vulnerability. First 200 chars: "
                                f"{response.text[:200]}"
                            ),
                            remediation=(
                                "Block access to 169.254.169.254 from external requests. "
                                "Use IMDSv2 with token requirement. Implement SSRF protections."
                            ),
                        )
                    )

            except (Timeout, RequestException):
                # Expected — endpoint shouldn't be reachable from outside
                pass

        # Also check if the target domain itself can be used as an SSRF proxy
        ssrf_paths = [
            f"https://{self.domain}/@169.254.169.254/latest/meta-data/",
            f"https://{self.domain}/?url=http://169.254.169.254/latest/meta-data/",
            f"https://{self.domain}/proxy?url=http://169.254.169.254/latest/meta-data/",
            f"https://{self.domain}/fetch?url=http://169.254.169.254/latest/meta-data/",
        ]

        for path in ssrf_paths:
            try:
                response = self.session.get(path, timeout=5)
                if response.status_code == 200 and ("ami-id" in response.text or "instance-id" in response.text):
                    self.findings.append(
                        Finding(
                            title=f"Potential SSRF via target: {path}",
                            severity=Severity.CRITICAL,
                            service="SSRF-Recon",
                            resource=path,
                            detail="Target appears to proxy requests to cloud metadata endpoint",
                            remediation="Validate and sanitize all URL inputs. Block internal IP ranges.",
                        )
                    )
            except (Timeout, RequestException):
                pass

    def _check_sensitive_paths(self) -> None:
        """Check for exposed sensitive files on the target domain.

        Tests for common misconfigurations that expose credentials,
        source code, or configuration files.
        """
        print("  \033[36m→\033[0m Checking sensitive file exposure...")

        for path in SENSITIVE_PATHS:
            url = f"https://{self.domain}{path}"

            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)

                # Check for actual content (not 404 pages or redirects)
                if response.status_code == 200:
                    content = response.text.lower()

                    # Verify the response contains expected content
                    is_relevant = False
                    if ".env" in path and ("=" in content or "key" in content or "secret" in content):
                        is_relevant = True
                    elif ".git/config" in path and ("[core]" in content or "[remote" in content):
                        is_relevant = True
                    elif ".git/HEAD" in path and "ref:" in content:
                        is_relevant = True
                    elif "wp-config" in path and ("db_" in content or "DB_" in content):
                        is_relevant = True
                    elif "config.json" in path and ("{" in content and "}" in content):
                        is_relevant = True
                    elif "docker-compose" in path and ("services:" in content or "image:" in content):
                        is_relevant = True
                    elif "Dockerfile" in path and ("FROM " in content or "RUN " in content):
                        is_relevant = True
                    elif "phpinfo" in path and "phpinfo" in content:
                        is_relevant = True
                    elif "server-status" in path and "server status" in content:
                        is_relevant = True
                    elif "serviceAccountKey" in path and "private_key" in content:
                        is_relevant = True
                    elif "credentials" in path and ("{" in content or "key" in content):
                        is_relevant = True
                    elif path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                        is_relevant = True  # These are always relevant
                    else:
                        # Generic check for other paths
                        if len(content) > 50:
                            is_relevant = True

                    if is_relevant:
                        severity = Severity.HIGH

                        # Escalate for credential files
                        if any(kw in path for kw in [".env", ".git", "credentials", "serviceAccount"]):
                            severity = Severity.CRITICAL

                        # Downgrade for informational files
                        if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                            severity = Severity.INFO

                        self.findings.append(
                            Finding(
                                title=f"Exposed sensitive file: {path}",
                                severity=severity,
                                service="Web-Recon",
                                resource=f"{self.domain}{path}",
                                detail=(
                                    f"File accessible at https://{self.domain}{path} "
                                    f"(HTTP {response.status_code}, {len(response.text)} bytes)"
                                ),
                                remediation=(
                                    "Remove the file or restrict access. "
                                    "Add to .gitignore and rotate any exposed credentials."
                                ),
                            )
                        )

            except (Timeout, RequestException):
                continue

    def _check_cloud_headers(self) -> None:
        """Analyze HTTP response headers for cloud service indicators.

        Detects which cloud provider is serving the target and flags
        any information-leaking headers.
        """
        print("  \033[36m→\033[0m Analyzing cloud HTTP headers...")

        url = f"https://{self.domain}/"

        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except (Timeout, RequestException):
            # Try HTTP fallback
            try:
                url = f"http://{self.domain}/"
                response = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            except (Timeout, RequestException):
                return

        detected_clouds: set[str] = set()
        leaking_headers: list[str] = []

        for header_name, cloud_service in CLOUD_HEADERS.items():
            header_value = response.headers.get(header_name)
            if header_value:
                detected_clouds.add(cloud_service)
                leaking_headers.append(f"{header_name}: {header_value[:80]}")

        if detected_clouds:
            self.findings.append(
                Finding(
                    title=f"Cloud services detected: {', '.join(detected_clouds)}",
                    severity=Severity.INFO,
                    service="Header-Recon",
                    resource=self.domain,
                    detail=(
                        f"Response headers indicate hosting on: {', '.join(detected_clouds)}. "
                        f"Headers: {'; '.join(leaking_headers[:5])}"
                    ),
                    remediation=(
                        "Remove or minimize information-leaking HTTP headers. "
                        "Configure your CDN/proxy to strip backend headers."
                    ),
                )
            )

        # Check for security headers missing
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "XCTO",
            "X-Frame-Options": "XFO",
        }

        missing_headers: list[str] = []
        for header, label in security_headers.items():
            if not response.headers.get(header):
                missing_headers.append(label)

        if missing_headers:
            self.findings.append(
                Finding(
                    title=f"Missing security headers: {', '.join(missing_headers)}",
                    severity=Severity.LOW,
                    service="Header-Recon",
                    resource=self.domain,
                    detail=f"Missing: {', '.join(missing_headers)}",
                    remediation="Implement recommended security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options)",
                )
            )

    def _check_dns_cloud_records(self) -> None:
        """Check DNS records for cloud hosting indicators.

        Looks for CNAME records pointing to cloud services,
        which reveals the cloud provider hosting the domain.
        """
        print("  \033[36m→\033[0m Checking DNS cloud indicators...")

        cloud_cname_patterns = {
            "amazonaws.com": "AWS",
            "cloudfront.net": "AWS CloudFront",
            "elasticbeanstalk.com": "AWS Elastic Beanstalk",
            "elb.amazonaws.com": "AWS ELB",
            "s3-website": "AWS S3 Static Website",
            "azurewebsites.net": "Azure App Service",
            "cloudapp.net": "Azure Cloud Services",
            "blob.core.windows.net": "Azure Blob Storage",
            "trafficmanager.net": "Azure Traffic Manager",
            "c.storage.googleapis.com": "GCP Storage",
            "cloudfunctions.net": "GCP Cloud Functions",
            "run.app": "GCP Cloud Run",
            "cloudflare.com": "Cloudflare",
            "fastly.net": "Fastly CDN",
            "herokuapp.com": "Heroku",
            "netlify.app": "Netlify",
            "vercel.app": "Vercel",
            "firebaseapp.com": "Firebase",
        }

        try:
            # Try to resolve CNAME for the domain
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", self.domain],
                capture_output=True,
                text=True,
                timeout=10,
            )

            cname_records = [r.strip().rstrip(".") for r in result.stdout.strip().split("\n") if r.strip()]

            # Also check A records for cloud IP ranges
            a_result = subprocess.run(
                ["dig", "+short", "A", self.domain],
                capture_output=True,
                text=True,
                timeout=10,
            )

            a_records = [r.strip() for r in a_result.stdout.strip().split("\n") if r.strip()]

            for cname in cname_records:
                for pattern, provider in cloud_cname_patterns.items():
                    if pattern in cname.lower():
                        self.findings.append(
                            Finding(
                                title=f"DNS reveals cloud provider: {provider}",
                                severity=Severity.INFO,
                                service="DNS-Recon",
                                resource=self.domain,
                                detail=(
                                    f"CNAME record {cname} points to {provider}. "
                                    f"This reveals the hosting infrastructure."
                                ),
                                remediation=(
                                    "Consider using a proxy/CDN that masks origin CNAME records. "
                                    "Use DNS-level security (DNSSEC, CAA records)."
                                ),
                            )
                        )

            # Check for subdomain takeover risk
            if cname_records and a_records:
                for cname in cname_records:
                    for pattern, provider in cloud_cname_patterns.items():
                        if pattern in cname.lower():
                            # Check if the CNAME target actually resolves
                            target_result = subprocess.run(
                                ["dig", "+short", "A", cname],
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )
                            target_a = target_result.stdout.strip()

                            if not target_a:
                                self.findings.append(
                                    Finding(
                                        title=f"Potential subdomain takeover: {self.domain} → {cname}",
                                        severity=Severity.CRITICAL,
                                        service="DNS-Recon",
                                        resource=self.domain,
                                        detail=(
                                            f"CNAME points to {cname} ({provider}) but the target "
                                            f"does not resolve — potential subdomain takeover!"
                                        ),
                                        remediation=(
                                            "Remove the dangling DNS record immediately. "
                                            "If the cloud resource is still needed, recreate it. "
                                            "Otherwise, delete the CNAME record."
                                        ),
                                    )
                                )

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            # dig not available or timed out
            pass
