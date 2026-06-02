# prod_audit.py — AWS Production Audit Script

**Version:** 4.0  
**Author:** Security Team, Shyftlabs  
**Controls:** 138 across 43 AWS services

---

## What it does

Runs a point-in-time security and backup audit against your AWS account. For each control it reports PASS, FAIL, WARN, or SKIP along with a plain-English detail message and a one-line remediation command.

Results are displayed in the terminal and exported to Excel (one tab per service) or JSON.

---

## Prerequisites

Python 3.8+ and an AWS account with credentials configured.

```bash
pip install boto3 rich pandas openpyxl
```

Your IAM identity needs read-only access across the audited services. The broadest managed policy that covers everything is `ReadOnlyAccess`, but any policy that grants `Describe*`, `List*`, and `Get*` on the relevant services will work.

---

## Quick start

```bash
# Run with interactive region prompt
python prod_audit.py

# Specify a region directly
python prod_audit.py --region ca-central-1

# Use a named AWS CLI profile
python prod_audit.py --profile my-sso-profile
```
<img width="1914" height="522" alt="image" src="https://github.com/user-attachments/assets/ec614994-42c0-4bbd-898a-c16afe791408" />


---

## All options

| Flag | Description |
|---|---|
| `--region REGION` | AWS region to audit. Auto-detects from `AWS_DEFAULT_REGION` or `~/.aws/config`. Prompts interactively if not set. |
| `--profile NAME` | Named AWS CLI profile (e.g. `my-sso-profile`). |
| `--output PATH` | Output file path. Defaults to `<AccountName>_<timestamp>.xlsx` or `.json`. |
| `--output-format` | `xlsx` (default) or `json` for CI/CD pipeline integration. |
| `--check-only SERVICE ...` | Run only the specified service(s). See `--list-checks` for valid keys. |
| `--severity-filter LEVEL` | Show only `critical`, `high`, `medium`, or `low` results in the terminal table. |
| `--list-checks` | Print all 43 service keys and exit. No AWS calls made. |
| `--no-excel` | Skip file export — terminal output only. |
| `--notify-slack URL` | Post a summary to a Slack incoming webhook after the run. |

---

## Usage examples

```bash
# Audit only IAM, S3, and GuardDuty
python prod_audit.py --check-only iam s3 guardduty

# Show only critical failures in the terminal
python prod_audit.py --severity-filter critical

# Export to JSON instead of Excel
python prod_audit.py --output-format json

# Full audit with Slack notification
python prod_audit.py --region eu-west-1 --notify-slack https://hooks.slack.com/services/...

# Quick critical-only scan, no file output
python prod_audit.py --check-only iam guardduty securityhub --severity-filter critical --no-excel

# See all available service keys
python prod_audit.py --list-checks
```

---

## Services covered

| Key | Service |
|---|---|
| `ebs` | EBS volumes and DLM snapshot policies |
| `rds` | RDS instances |
| `dynamodb` | DynamoDB tables |
| `s3` | S3 buckets |
| `memorydb` | MemoryDB clusters |
| `eks` | EKS clusters |
| `msk` | MSK (Kafka) clusters |
| `kms` | KMS customer-managed keys |
| `secrets` | Secrets Manager |
| `sqs` | SQS queues and DLQs |
| `lambda` | Lambda functions |
| `apigateway` | API Gateway REST APIs |
| `cloudtrail` | CloudTrail trails |
| `route53` | Route 53 hosted zones, domains, ACM certs |
| `ecr` | ECR repositories |
| `config` | AWS Config (all enabled regions) |
| `ses` | SES identities and configuration sets |
| `amplify` | Amplify apps |
| `vpc` | VPCs, security groups, flow logs |
| `cognito` | Cognito user pools |
| `cloudformation` | CloudFormation stacks |
| `elb` | ALBs and NLBs |
| `cloudwatch` | CloudWatch alarms and dashboards |
| `cwlogs` | CloudWatch Logs log groups |
| `ssm` | SSM parameters and associations |
| `eventbridge` | EventBridge rules and schedules |
| `guardduty` | GuardDuty detectors and findings |
| `iam` | IAM users, roles, root account |
| `awsbackup` | AWS Backup plans, vaults, jobs |
| `cloudfront` | CloudFront distributions |
| `costexplorer` | Cost anomaly monitors and budgets |
| `sns` | SNS topics and subscriptions |
| `stepfunctions` | Step Functions state machines |
| `waf` | WAFv2 regional ACLs |
| `elasticache` | ElastiCache replication groups |
| `securityhub` | Security Hub findings and standards |
| `macie` | Macie findings and discovery |
| `athena` | Athena workgroups and Glue catalog |
| `transitgateway` | Transit Gateway attachments and flow logs |
| `apprunner` | App Runner services |
| `xray` | X-Ray sampling rules and Lambda tracing |
| `bedrock` | Bedrock guardrails, logging, knowledge bases |

---

## Output

**Terminal** — colour-coded table per service with ID, control name, severity, status, detail, and remediation hint.

**Excel** (`--output-format xlsx`) — one sheet per service plus a top-level summary sheet. Cells are colour-coded by status (green = PASS, red = FAIL, yellow = WARN, grey = SKIP) and severity.

**JSON** (`--output-format json`) — structured output suitable for ingestion by SIEM tools or CI/CD pipelines.

```json
{
  "meta": { "account_id": "123456789012", "region": "ca-central-1", "score_pct": 74, ... },
  "controls": [
    { "check_id": "S3-001", "status": "FAIL", "detail": "...", "remediation": "..." },
    ...
  ]
}
```

---

## Status meanings

| Status | Meaning |
|---|---|
| PASS | Control is satisfied |
| FAIL | Control is violated — remediation required |
| WARN | Partial or unverifiable — manual review recommended |
| SKIP | Could not run the check (no resources found or API error) |

---

## Notes

- The script is read-only — it makes no changes to your AWS environment.
- Checks that require internal VPC access (MSK topic replication, MemoryDB subnet validation) are marked WARN and require manual follow-up.
- The Config check (`config`) queries all enabled regions concurrently. On accounts with many regions this is the slowest check.
- For large accounts with hundreds of Lambda functions or DynamoDB tables, the audit may take 5–10 minutes.
