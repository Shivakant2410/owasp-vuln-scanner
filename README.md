# ☁️ Cloud Security Auditor

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS](https://img.shields.io/badge/AWS-Security%20Audit-orange.svg)](https://aws.amazon.com/security/)
[![CIS Benchmark](https://img.shields.io/badge/CIS-AWS%20Foundations-green.svg)](https://www.cisecurity.org/benchmark/amazon_web_services)

A comprehensive **AWS cloud security auditing toolkit** designed for offensive security professionals and penetration testers. Performs automated security assessment of AWS infrastructure and external cloud attack surface reconnaissance.

> Built with a focus on **cloud security assessment** — the critical skill for modern offensive security engagements.

## 🎯 Features

### AWS Infrastructure Audit (Authenticated)
- **S3 Scanner** — Public buckets, wildcard policies, missing encryption, disabled versioning/logging, sensitive file detection
- **IAM Analyzer** — Root account usage, missing MFA, stale access keys, admin privileges, weak password policies, inline policies
- **EC2 Auditor** — Open security groups (SSH/RDP to world), public instances, missing IAM roles, unencrypted EBS volumes, deprecated instance types
- **Network Auditor** — Missing VPC flow logs, permissive NACLs, suspicious route tables, mislabeled public subnets
- **Logging Checker** — CloudTrail coverage, CloudWatch security alarms, AWS Config rules, GuardDuty status, S3 Block Public Access
- **Compliance Checker** — CIS AWS Foundations Benchmark assessment with pass/fail scoring per control

### External Reconnaissance (No Credentials Required)
- **S3 Bucket Discovery** — DNS-based detection of exposed buckets using naming conventions
- **Azure Blob Detection** — Public Azure Storage container discovery
- **GCP Storage Discovery** — Exposed Google Cloud Storage bucket detection
- **SSRF Vector Testing** — Cloud metadata endpoint exposure (169.254.169.254)
- **Sensitive File Exposure** — .env, .git, credentials, config files on target domain
- **Cloud Header Analysis** — Detect cloud provider via HTTP response headers
- **DNS Cloud Recon** — CNAME-based cloud provider detection, subdomain takeover risk
- **Security Header Audit** — Missing HSTS, CSP, X-Frame-Options, etc.

### Reporting
- **Color-coded console output** with severity badges
- **JSON export** for programmatic processing
- **Dark-themed HTML report** with interactive filtering and executive summary
- **Risk scoring** (0-100) with severity-weighted calculation
- **Compliance score** mapped to CIS AWS Foundations Benchmark
- **Priority remediation list** for critical/high findings

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cloud-security-auditor.git
cd cloud-security-auditor

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### AWS Credentials Setup (for authenticated scans)

```bash
# Configure AWS CLI with your profile
aws configure --profile audit-profile

# Or use environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

**Recommended:** Use a read-only IAM role with the following permissions for auditing:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetPublicAccessBlock",
        "s3:ListObjects",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:GetLoginProfile",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:GetAccountPasswordPolicy",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSubnets",
        "ec2:DescribeInternetGateways",
        "ec2:GetEbsEncryptionByDefault",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudwatch:DescribeAlarms",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigRules",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "s3control:GetPublicAccessBlock",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## 🚀 Usage

### Full AWS Security Audit

```bash
# Audit all services with default profile
python main.py --profile default --region us-east-1

# Audit specific services only
python main.py --profile default --service s3 --service iam

# Generate HTML report
python main.py --profile default --output html --output-file audit_report.html

# Generate both JSON and HTML
python main.py --profile default --output both --output-file audit_report

# Filter to only show CRITICAL and HIGH findings
python main.py --profile default --min-severity HIGH
```

### External Reconnaissance (No AWS Credentials)

```bash
# Scan a domain for cloud exposures
python main.py --standalone --domain example.com

# Generate HTML recon report
python main.py --standalone --domain example.com --output html --output-file recon_report.html

# JSON output for integration
python main.py --standalone --domain example.com --output json --output-file recon.json
```

### Programmatic Usage

```python
from cloud_auditor.core import CloudAuditor
from cloud_auditor.external_recon import ExternalRecon
from cloud_auditor.report_generator import ReportGenerator

# AWS audit
auditor = CloudAuditor(profile="default", region="us-east-1")
findings = auditor.run(services=["s3", "iam", "ec2"])

# Generate reports
generator = ReportGenerator(findings)
generator.export_json("report.json")
generator.export_html("report.html")

# External recon (no AWS credentials)
recon = ExternalRecon("example.com")
recon_findings = recon.scan()
for finding in recon_findings:
    print(f"[{finding.severity.value}] {finding.title}")
```

## 🏗️ Architecture

```
cloud-security-auditor/
├── main.py                          # CLI entry point
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
└── cloud_auditor/
    ├── __init__.py                  # Package init
    ├── core.py                      # Main CloudAuditor orchestrator
    ├── findings.py                  # Finding/Severity/FindingSet data models
    ├── s3_scanner.py                # S3 bucket security assessment
    ├── iam_analyzer.py              # IAM security analysis
    ├── ec2_auditor.py               # EC2 instance/volume auditing
    ├── network_auditor.py           # VPC/network security checks
    ├── logging_checker.py           # CloudTrail/CloudWatch/Config/GuardDuty
    ├── compliance_checker.py        # CIS AWS Foundations Benchmark
    ├── report_generator.py          # JSON & HTML report generation
    └── external_recon.py            # Credential-less cloud recon
```

## 🔍 Example Output

### Console Output
```
 ╔═══════════════════════════════════════════════════════════╗
 ║          ☁️  CLOUD SECURITY AUDITOR v1.2.0  ☁️            ║
 ║         AWS Infrastructure Security Assessment            ║
 ╠═══════════════════════════════════════════════════════════╣
 ║  Target:  AWS Account: 123456789012                      ║
 ║  Region:  us-east-1                                      ║
 ║  Time:    2024-01-15 14:30:00 UTC                        ║
 ╚═══════════════════════════════════════════════════════════╝

============================================================
  CLOUD SECURITY AUDIT RESULTS
============================================================
  Account:   123456789012
  Risk Score: 67.3/100
  Total Findings: 12
    CRITICAL: 2
    HIGH: 3
    MEDIUM: 4
    LOW: 2
    INFO: 1
============================================================

  [CRITICAL] SSH (22) open to world: default-sg
    Service:   EC2
    Resource:  sg-0abc1234
    Detail:    Security group 'default-sg' allows SSH (port 22) from 0.0.0.0/0
    Fix:       Restrict port 22 to specific IP ranges. Use a bastion host or VPN.
    Compliance:CIS 4.1 CIS 4.2
```

### HTML Report
The HTML report features:
- 🎨 Dark cybersecurity theme
- 📊 Interactive risk score gauge
- 🔍 Click-to-filter by service
- ⚖️ CIS compliance score with pass/fail per control
- 📋 Priority remediation list

## 🛡️ Security Disclaimer

This tool is designed for **authorized security assessment purposes only**. 

- Always obtain proper authorization before scanning any infrastructure
- The external reconnaissance module performs non-invasive checks only (DNS resolution, HTTP GET requests)
- Do not use this tool against systems you do not own or have explicit permission to test
- The authors are not responsible for misuse of this tool
- Follow your organization's security testing policies and applicable laws

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

**Built for cloud security assessment professionals.** ☁️🔒
