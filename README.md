
<div align="center">

# 🛡️ AWS Production Audit & Backup Compliance Tool

### 🚀 Production Security • Backup • Resiliency • Compliance Assessment Framework

*Validate 138 AWS production controls in a single command.*

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Audit-FF9900?style=for-the-badge&logo=amazonaws)
![Controls](https://img.shields.io/badge/Controls-138-success?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-4.0-blue?style=for-the-badge)
![Author](https://img.shields.io/badge/Author-Security_Team_Shyftlabs-red?style=for-the-badge)

</div>

---

# ✨ What is this?

AWS Production Audit Tool is a comprehensive assessment framework that validates **138 production-grade controls** across your AWS environment.

The tool automatically evaluates:

- 🔐 Security Controls
- 💾 Backup & Recovery Readiness
- 📊 Monitoring & Logging
- ☁️ Infrastructure Resiliency
- 🚨 Disaster Recovery Posture
- 📋 Operational Best Practices

and generates detailed Excel and JSON reports with evidence and remediation guidance.

---

# 🚀 Key Features

✅ 138 Automated Controls  
✅ Excel Report Generation  
✅ JSON Export Support  
✅ Severity-Based Findings  
✅ Slack Notifications  
✅ Multi-Region Support  
✅ Progress Tracking  
✅ Built-in Remediation Guidance  
✅ Rich Terminal Dashboard

---

# ☁️ AWS Services Covered

| 🖥️ Compute | 💾 Storage & Backup | 🔐 Security | 📊 Monitoring | 🚀 Platform Services |
|:-----------|:--------------------|:------------|:--------------|:---------------------|
| EC2 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | EBS &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | IAM &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | CloudTrail &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Cognito |
| Lambda | S3 | KMS | CloudWatch | Route53 |
| EKS | DynamoDB | GuardDuty | AWS Config | CloudFormation |
| App Runner | RDS | Security Hub | X-Ray | ECR |
|  | AWS Backup | Macie |  | EventBridge |
|  | MemoryDB | WAF |  | Secrets Manager |
|  |  |  |  | Bedrock |

---

# ⚙️ Installation

```bash
pip install boto3 pandas openpyxl rich
```

Configure AWS:

```bash
aws configure
```

or

```bash
aws configure sso
```

Verify:

```bash
aws sts get-caller-identity
```

---

# ▶️ Usage

Run full audit:

```bash
python prod_audit.py
```

Specific region:

```bash
python prod_audit.py --region ca-central-1
```

AWS profile:

```bash
python prod_audit.py --profile production
```

JSON output:

```bash
python prod_audit.py --output-format json
```

Critical findings only:

```bash
python prod_audit.py --severity-filter critical
```

Slack notification:

```bash
python prod_audit.py --notify-slack <webhook-url>
```

---

# 🔄 Audit Workflow

1. Discover AWS Account
2. Enumerate Resources
3. Execute 138 Controls
4. Collect Findings
5. Generate Excel Report
6. Generate JSON Report
7. Send Slack Summary
8. Display Executive Dashboard

---

# 📊 Sample Findings

| Control | Severity | Status |
|----------|----------|----------|
| IAM-001 | Critical | ❌ FAIL |
| S3-001 | Critical | ✅ PASS |
| CT-001 | Critical | ✅ PASS |
| RDS-002 | Critical | ❌ FAIL |

---

# 📁 Output

Report naming:

```text
<AWS_Account_Name>_<Timestamp>.xlsx
```

Example:

```text
Production_2026-08-13_15-45-00.xlsx
```

Report contains:

- Control ID
- Service
- Severity
- Status
- Evidence
- Detail
- Remediation

---

# 📦 Requirements

```text
boto3
pandas
openpyxl
rich
```

---

# 🛠️ Troubleshooting

### Missing Credentials

```bash
aws configure
```

### Missing Modules

```bash
pip install -r requirements.txt
```

### Verify Access

```bash
aws sts get-caller-identity
```

---

# 📜 Changelog

| Version | Notes |
|----------|----------|
| 4.0 | 138 Controls, JSON Output, Slack Support |
| 3.0 | Security & Backup Framework |
| 2.0 | Reporting Enhancements |
| 1.0 | Initial Release |

---

<div align="center">

## 🛡️ Security Team, Shyftlabs

**Secure • Audit • Validate • Improve**

</div>
