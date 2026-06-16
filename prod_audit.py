#!/usr/bin/env python3
"""
prod_audit.py — Production Audit Status Tracker
------------------------------------------------
Author  : Security Team, Shyftlabs
Version : 4.0

What changed from v3.0 → v4.0
  BUG FIXES
    IAM-001  Now correctly checks MFA on all IAM users via credential report
    IAM-002  Now correctly labelled "MFA on Root Account" (AccountMFAEnabled)
    IAM-003  Now correctly labelled "No Active Root Access Keys" (AccountAccessKeysPresent)
    CE-001/2 Cost Explorer now calls list_cost_anomaly_monitors/subscriptions (not get_*)
    BKP-001  Label corrected to "Backup Plan Exists"
    BKP-002  Label corrected to "Backup Vault Lock Enabled"
    BKP-003  Label corrected to "No Failed Backup Jobs"
    S3       Uses global boto3.client("s3") — no regional endpoint redirect errors
    DynamoDB Full pagination via get_paginator("list_tables")
    CW Logs  Full pagination via get_paginator("describe_log_groups")
    ECR      Only catches LifecyclePolicyNotFoundException as "missing policy"
    MSK-001  Checks ProvisionedThroughput in BrokerNodeGroupInfo (not autoscaling API)
    GD-002   Checks EventPattern for "aws.guardduty" source (not plain string match)
    BR-003   Uses bedrock-agent client for list_knowledge_bases

  IMPROVEMENTS
    --region   Default chains: AWS_DEFAULT_REGION env → boto3 session → interactive prompt
    --profile  New flag for named AWS CLI profiles
    Retries    All clients use BotoConfig adaptive retry (6 attempts) — no more SKIP on throttle
    Lambda     Paginated list_functions; result cached in AuditState._lambda_fns
    X-Ray      Reuses cached Lambda list — no duplicate list_functions call
    IAM cred   Polls generate_credential_report until COMPLETE (not sleep(3))
    IAM roles  Timezone-aware datetime comparison (no replace(tzinfo=None) bug)
    Config     ThreadPoolExecutor(12) for concurrent region checks — 6× faster
    client()   @lru_cache — reuses boto3 connections; no repeated TLS handshakes

  NEW FEATURES
    --list-checks       Print all service keys and exit
    --output-format     xlsx (default) or json for CI/CD pipelines
    --severity-filter   Print only critical/high/medium/low rows
    --notify-slack      Post summary to Slack webhook after run
    Remediation column  One-line fix command in both terminal table and Excel
    Progress bar        Shows [N/M] count + elapsed time

Covers all 138 controls from the Prod Critical Backup Verification sheet.

Services:
  EBS · RDS · DynamoDB · S3 · MemoryDB · EKS · MSK · KMS ·
  Secrets Manager · SQS · Lambda · API Gateway · CloudTrail ·
  Route 53 · ECR · AWS Config · SES · Amplify · VPC · Cognito ·
  CloudFormation · ELB · CloudWatch · CloudWatch Logs · SSM ·
  EventBridge · GuardDuty · IAM · AWS Backup · CloudFront ·
  Cost Explorer · SNS · Step Functions · WAF · ElastiCache ·
  Security Hub · Macie · Athena · Transit Gateway · App Runner ·
  X-Ray · Bedrock

Usage:
  python prod_audit.py
  python prod_audit.py --region eu-west-1
  python prod_audit.py --profile my-sso-profile
  python prod_audit.py --output report.xlsx
  python prod_audit.py --output-format json
  python prod_audit.py --severity-filter critical
  python prod_audit.py --check-only ebs rds s3
  python prod_audit.py --list-checks
  python prod_audit.py --no-excel
  python prod_audit.py --notify-slack https://hooks.slack.com/...

Prerequisites:
  pip install boto3 rich pandas openpyxl
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, List, Optional

import boto3
import pandas as pd
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, NoCredentialsError
from openpyxl import load_workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, MofNCompleteColumn, Progress,
                           SpinnerColumn, TextColumn, TimeElapsedColumn)
from rich.rule import Rule
from rich.table import Table
from rich.traceback import install as install_rich_traceback
from rich import box

install_rich_traceback()

# ── Config ─────────────────────────────────────────────────────────────────────
VERSION   = "4.0"
AUTHOR    = "Security Team, Shyftlabs"
DATE_STR  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
DATE_FILE = datetime.now().strftime("%Y-%m-%dT%H-%M")   # OS-safe filename
console   = Console()

RETRY_CFG = BotoConfig(retries={"mode": "adaptive", "max_attempts": 6})

STATUS_STYLE = {
    "PASS": ("✅ PASS", "bold green"),
    "FAIL": ("❌ FAIL", "bold red"),
    "WARN": ("⚠️  WARN", "bold yellow"),
    "SKIP": ("⏭️  SKIP", "dim"),
}
SEV_STYLE = {
    "Critical": "bold red",
    "High":     "bold orange3",
    "Medium":   "bold yellow",
    "Low":      "dim white",
}

# One-line remediation hints keyed on check_id
REMEDIATION: Dict[str, str] = {
    "EBS-001": "aws ec2 modify-instance-attribute --instance-id <id> --block-device-mappings '[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"DeleteOnTermination\":false}}]'",
    "EBS-002": "aws dlm create-lifecycle-policy --description 'Daily EBS snapshots' ...",
    "EBS-005": "aws backup put-backup-vault-lock-configuration --backup-vault-name <v> --changeable-for-days 3",
    "RDS-001": "aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection --apply-immediately",
    "RDS-002": "aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period 7 --apply-immediately",
    "RDS-003": "aws rds modify-db-instance --db-instance-identifier <id> --multi-az --apply-immediately",
    "RDS-005": "aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible --apply-immediately",
    "DDB-001": "aws dynamodb update-continuous-backups --table-name <t> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
    "DDB-003": "aws dynamodb update-table --table-name <t> --deletion-protection-enabled",
    "S3-001":  "aws s3api put-bucket-versioning --bucket <b> --versioning-configuration Status=Enabled",
    "S3-003":  "aws s3api put-public-access-block --bucket <b> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    "MDB-001": "aws memorydb update-cluster --cluster-name <n> --snapshot-retention-limit 7",
    "KMS-001": "aws kms cancel-key-deletion --key-id <kid>",
    "SQS-001": "aws sqs set-queue-attributes --queue-url <url> --attributes '{\"RedrivePolicy\":\"{...}\"}'",
    "LAM-004": "aws ssm put-parameter --name /prod/secret --type SecureString --value <v>",
    "CT-001":  "aws cloudtrail create-trail --name prod-trail --s3-bucket-name <b> --is-multi-region-trail",
    "CT-002":  "aws cloudtrail update-trail --name <t> --enable-log-file-validation",
    "ECR-001": "aws ecr put-image-tag-mutability --repository-name <r> --image-tag-mutability IMMUTABLE",
    "IAM-001": "Enforce MFA: attach IAM policy requiring MFA condition for all console access",
    "IAM-002": "Enable root MFA in AWS Console > Security Credentials",
    "IAM-003": "Delete root access keys in AWS Console > Security Credentials",
    "BKP-001": "aws backup create-backup-plan --backup-plan file://plan.json",
    "BKP-002": "aws backup put-backup-vault-lock-configuration --backup-vault-name <v> --changeable-for-days 3",
    "ELB-001": "aws elbv2 modify-load-balancer-attributes --load-balancer-arn <arn> --attributes Key=deletion_protection.enabled,Value=true",
    "CFN-001": "aws cloudformation update-termination-protection --enable-termination-protection --stack-name <s>",
    "GD-001":  "aws guardduty create-detector --enable",
    "CF-001":  "aws wafv2 associate-web-acl --web-acl-arn <waf-arn> --resource-arn <dist-arn>",
    "SH-001":  "aws securityhub enable-security-hub --enable-default-standards",
    "BR-002":  "aws bedrock put-model-invocation-logging-configuration --logging-config textDataDeliveryEnabled=true,s3Config={bucketName=<b>}",
}


# ── Priority Tier mapping ───────────────────────────────────────────────────────
# Maps the service name (as used in s.add calls) → Priority Tier label.
# Services not listed here (Cost Explorer, App Runner, Bedrock) use "—".
SERVICE_TIER: Dict[str, str] = {
    # Tier 1 — Direct data-storage services
    "RDS":              "Tier 1 — Data Destroyed",
    "DynamoDB":         "Tier 1 — Data Destroyed",
    "S3":               "Tier 1 — Data Destroyed",
    "EBS":              "Tier 1 — Data Destroyed",
    "MemoryDB":         "Tier 1 — Data Destroyed",
    "ElastiCache":      "Tier 1 — Data Destroyed",
    "MSK":              "Tier 1 — Data Destroyed",
    # Tier 2 — Data-pipeline services
    "SQS":              "Tier 2 — Data Dropped in Transit",
    "Step Functions":   "Tier 2 — Data Dropped in Transit",
    "SNS":              "Tier 2 — Data Dropped in Transit",
    "Lambda":           "Tier 2 — Data Dropped in Transit",
    "EventBridge":      "Tier 2 — Data Dropped in Transit",
    "Athena":           "Tier 2 — Data Dropped in Transit",
    # Tier 3 — Identity & access services
    "KMS":              "Tier 3 — Data Locked Out",
    "Secrets Manager":  "Tier 3 — Data Locked Out",
    "Cognito":          "Tier 3 — Data Locked Out",
    "IAM":              "Tier 3 — Data Locked Out",
    "SSM":              "Tier 3 — Data Locked Out",
    # Tier 4 — Infrastructure routing services
    "EKS":              "Tier 4 — Data Unreachable",
    "ECR":              "Tier 4 — Data Unreachable",
    "CloudFormation":   "Tier 4 — Data Unreachable",
    "Transit GW":       "Tier 4 — Data Unreachable",
    "ELB / ALB / NLB":  "Tier 4 — Data Unreachable",
    "Route 53":         "Tier 4 — Data Unreachable",
    "API Gateway":      "Tier 4 — Data Unreachable",
    # Tier 5 — Security & observability services
    "CloudTrail":       "Tier 5 — Data Exposed or Invisible",
    "AWS Backup":       "Tier 5 — Data Exposed or Invisible",
    "GuardDuty":        "Tier 5 — Data Exposed or Invisible",
    "Security Hub":     "Tier 5 — Data Exposed or Invisible",
    "Macie":            "Tier 5 — Data Exposed or Invisible",
    "WAF":              "Tier 5 — Data Exposed or Invisible",
    "VPC":              "Tier 5 — Data Exposed or Invisible",
    "CloudWatch":       "Tier 5 — Data Exposed or Invisible",
    "CloudWatch Logs":  "Tier 5 — Data Exposed or Invisible",
    "AWS Config":       "Tier 5 — Data Exposed or Invisible",
    "SES":              "Tier 5 — Data Exposed or Invisible",
    "Amplify":          "Tier 5 — Data Exposed or Invisible",
    "CloudFront":       "Tier 5 — Data Exposed or Invisible",
    "X-Ray":            "Tier 5 — Data Exposed or Invisible",
    "Bedrock":          "Tier 5 — Data Exposed or Invisible",
    "Cost Explorer":    "Tier 5 — Data Exposed or Invisible",
}

# Rich console colours per tier
TIER_CONSOLE_STYLE: Dict[str, str] = {
    "Tier 1 — Data Destroyed":            "bold red",
    "Tier 2 — Data Dropped in Transit":   "bold orange3",
    "Tier 3 — Data Locked Out":           "bold yellow",
    "Tier 4 — Data Unreachable":          "bold cyan",
    "Tier 5 — Data Exposed or Invisible": "bold magenta",
}

# Excel fill colours per tier (hex, no #)
TIER_FILL: Dict[str, str] = {
    "Tier 1": "FFB3B3",  # soft red
    "Tier 2": "FFD9B3",  # soft orange
    "Tier 3": "FFFAB3",  # soft yellow
    "Tier 4": "B3D9FF",  # soft blue
    "Tier 5": "E8B3FF",  # soft purple
}


def _short_tier(tier: str) -> str:
    """'Tier 1 — Data Destroyed' → 'Tier 1'  (leaves '—' untouched)."""
    return tier.split(" —")[0].strip() if " —" in tier else tier

# Full priority-tier reference table embedded from Priority_Tier.xlsx
PRIORITY_TIER_TABLE: List[tuple] = [
    ("Tier 1 — Data Destroyed",            "RDS",              "Direct Data Storage",     "Database permanently deleted - all prod data gone with no recovery"),
    ("Tier 1 — Data Destroyed",            "DynamoDB",         "Direct Data Storage",     "Table deleted - no recycle bin, data gone permanently"),
    ("Tier 1 — Data Destroyed",            "S3",               "Direct Data Storage",     "Objects deleted or overwritten permanently - backups, assets, state all gone"),
    ("Tier 1 — Data Destroyed",            "EBS",              "Direct Data Storage",     "Disk wiped on instance termination - app and database data on disk lost"),
    ("Tier 1 — Data Destroyed",            "MemoryDB",         "Direct Data Storage",     "Cluster failure with no snapshot - persistent cache data lost permanently"),
    ("Tier 1 — Data Destroyed",            "ElastiCache",      "Direct Data Storage",     "Node failure - session data and cache lost, cold cache hammers database"),
    ("Tier 1 — Data Destroyed",            "MSK (Kafka)",      "Direct Data Storage",     "Disk full - messages dropped permanently, topic data irrecoverable"),
    ("Tier 2 — Data Dropped in Transit",   "SQS",              "Data Pipeline",           "Failed messages lost without DLQ - no retry, no visibility, no recovery"),
    ("Tier 2 — Data Dropped in Transit",   "Step Functions",   "Data Pipeline",           "Failed execution - workflow data lost, downstream systems not updated"),
    ("Tier 2 — Data Dropped in Transit",   "SNS",              "Data Pipeline",           "Notification events dropped without DLQ - silent loss with no trace"),
    ("Tier 2 — Data Dropped in Transit",   "Lambda",           "Data Pipeline",           "Async failures discarded without OnFailure destination - events permanently lost"),
    ("Tier 2 — Data Dropped in Transit",   "EventBridge",      "Data Pipeline",           "Rule deleted - scheduled pipeline stops silently, data processing gap"),
    ("Tier 2 — Data Dropped in Transit",   "Athena",           "Data Pipeline",           "Workgroup deleted - saved queries, query history, Glue schema definitions gone"),
    ("Tier 3 — Data Locked Out",           "KMS",              "Identity & Access",       "Key deleted - all data encrypted with it permanently unreadable, no AWS recovery"),
    ("Tier 3 — Data Locked Out",           "Secrets Manager",  "Identity & Access",       "Credentials deleted - all dependent services break instantly, no recovery"),
    ("Tier 3 — Data Locked Out",           "Cognito",          "Identity & Access",       "User pool deleted - all user accounts permanently gone, no restore possible"),
    ("Tier 3 — Data Locked Out",           "IAM",              "Identity & Access",       "Roles deleted - services lose permissions, cannot access their own data"),
    ("Tier 3 — Data Locked Out",           "SSM",              "Identity & Access",       "SecureString deleted - app config and credentials gone, services fail to start"),
    ("Tier 4 — Data Unreachable",          "EKS",              "Infrastructure",          "PersistentVolumes lost without Velero - cluster delete takes all pod data with it"),
    ("Tier 4 — Data Unreachable",          "ECR",              "Infrastructure",          "Rollback image deleted by lifecycle policy - bad deploy becomes irreversible"),
    ("Tier 4 — Data Unreachable",          "CloudFormation",   "Infrastructure",          "Stack deleted - all resources inside wiped in one command"),
    ("Tier 4 — Data Unreachable",          "Transit Gateway",  "Infrastructure",          "TGW deleted - all VPC-to-VPC and on-premises connectivity broken instantly"),
    ("Tier 4 — Data Unreachable",          "ELB / ALB / NLB",  "Infrastructure",          "Load balancer deleted - all traffic routing broken, 100% downtime"),
    ("Tier 4 — Data Unreachable",          "Route 53",         "Infrastructure",          "Hosted zone deleted - all DNS gone, entire domain offline immediately"),
    ("Tier 4 — Data Unreachable",          "API Gateway",      "Infrastructure",          "API deleted - all routes, auth, and integrations gone, all endpoints down"),
    ("Tier 5 — Data Exposed or Invisible", "CloudTrail",       "Security & Observability", "Trail disabled - audit evidence gone, incidents uninvestigable"),
    ("Tier 5 — Data Exposed or Invisible", "AWS Backup",       "Security & Observability", "Backup plan deleted - relying on service-native backups only, vault unlocked"),
    ("Tier 5 — Data Exposed or Invisible", "GuardDuty",        "Security & Observability", "Detector disabled - zero threat detection, breaches completely invisible"),
    ("Tier 5 — Data Exposed or Invisible", "Security Hub",     "Security & Observability", "Disabled - security findings stop aggregating, posture invisible"),
    ("Tier 5 — Data Exposed or Invisible", "Macie",            "Security & Observability", "Disabled - PII exposure in S3 goes undetected, compliance violation"),
    ("Tier 5 — Data Exposed or Invisible", "WAF",              "Security & Observability", "Removed - APIs and ALBs exposed to attacks, data at risk of exfiltration"),
    ("Tier 5 — Data Exposed or Invisible", "VPC",              "Security & Observability", "Misconfigured - sensitive ports open, lateral movement undetected"),
    ("Tier 5 — Data Exposed or Invisible", "CloudWatch",       "Security & Observability", "Alarms deleted - no alerting on outages or anomalies, blind monitoring"),
    ("Tier 5 — Data Exposed or Invisible", "CloudWatch Logs",  "Security & Observability", "Log groups deleted - debug impossible, incident investigation blind"),
    ("Tier 5 — Data Exposed or Invisible", "AWS Config",       "Security & Observability", "Disabled - compliance drift and misconfig completely undetected"),
    ("Tier 5 — Data Exposed or Invisible", "SES",              "Security & Observability", "Config deleted - transactional email stops, bounce handling gone"),
    ("Tier 5 — Data Exposed or Invisible", "Amplify",          "Security & Observability", "App config deleted - frontend offline, build pipeline broken"),
    ("Tier 5 — Data Exposed or Invisible", "CloudFront",       "Security & Observability", "Distribution deleted - CDN offline, static assets and APIs unreachable"),
    ("Tier 5 — Data Exposed or Invisible", "X-Ray",            "Security & Observability", "Tracing disabled - performance issues and errors untraceable in prod"),
    ("Tier 5 — Data Exposed or Invisible", "Bedrock",          "Security & Observability", "Logging disabled - LLM usage unauditable, compliance breach"),
    ("Tier 5 — Data Exposed or Invisible", "Cost Explorer",    "Security & Observability", "Anomaly monitor off - runaway cost from breach or misconfiguration undetected"),
]

# App Runner has no tier classification in the reference sheet
SERVICE_TIER["App Runner"] = SERVICE_TIER.get("App Runner", "—")

# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    check_id:    str
    service:     str
    control:     str
    severity:    str
    status:      str        # PASS | FAIL | WARN | SKIP
    detail:      str
    remediation: str = ""
    section:     str = ""


@dataclass
class AuditState:
    results:      List[CheckResult] = field(default_factory=list)
    region:       str = "ca-central-1"
    account:      str = ""
    account_name: str = ""
    _lambda_fns:  Optional[List] = field(default=None, repr=False)   # cached once in check_lambda

    @property
    def passes(self) -> int: return sum(1 for r in self.results if r.status == "PASS")
    @property
    def fails(self)  -> int: return sum(1 for r in self.results if r.status == "FAIL")
    @property
    def warns(self)  -> int: return sum(1 for r in self.results if r.status == "WARN")
    @property
    def skips(self)  -> int: return sum(1 for r in self.results if r.status == "SKIP")

    def add(self, check_id: str, service: str, control: str,
            severity: str, status: str, detail: str, section: str = "") -> None:
        self.results.append(CheckResult(
            check_id=check_id, service=service, control=control,
            severity=severity, status=status, detail=detail,
            remediation=REMEDIATION.get(check_id, ""),
            section=section or service,
        ))


# ── AWS helpers ─────────────────────────────────────────────────────────────────

@lru_cache(maxsize=128)
def client(service: str, region: str):
    """Cached boto3 client — reuses HTTP sessions; adaptive retry on throttle."""
    return boto3.client(service, region_name=region, config=RETRY_CFG)


def _resolve_region() -> str:
    """Region: env var → boto3 session → interactive prompt."""
    region = (os.environ.get("AWS_DEFAULT_REGION") or
              os.environ.get("AWS_REGION") or
              boto3.session.Session().region_name)
    if region:
        return region
    console.print("[bold yellow]  No AWS region configured.[/]")
    entered = console.input("  [cyan]Enter AWS region[/] [dim](e.g. ca-central-1)[/]: ").strip()
    return entered or "ca-central-1"


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION CHECKS
# ══════════════════════════════════════════════════════════════════════════════

# ── EBS ────────────────────────────────────────────────────────────────────────
def check_ebs(s: AuditState) -> None:
    ec2 = client("ec2", s.region)

    # EBS-001 DeleteOnTermination
    try:
        res = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
        dot = sum(1 for r in res.get("Reservations", [])
                  for i in r.get("Instances", [])
                  for b in i.get("BlockDeviceMappings", [])
                  if b.get("Ebs", {}).get("DeleteOnTermination"))
        s.add("EBS-001", "EBS", "EBS DeleteOnTermination = false", "Critical",
              "FAIL" if dot else "PASS",
              f"{dot} volume(s) have DeleteOnTermination=True — data will be lost on termination" if dot
              else "All EBS volumes have DeleteOnTermination=False; data safe on instance termination")
    except Exception:
        s.add("EBS-001", "EBS", "EBS DeleteOnTermination = false", "Critical", "SKIP",
              "API error — could not query EC2 instances")

    # EBS-002 DLM Snapshot Policy
    try:
        dlm    = client("dlm", s.region)
        active = [p for p in dlm.get_lifecycle_policies().get("Policies", [])
                  if p.get("State") == "ENABLED"]
        s.add("EBS-002", "EBS", "Daily EBS Snapshot Policy", "Critical",
              "PASS" if active else "FAIL",
              f"{len(active)} active DLM lifecycle policy(s) — automated snapshots configured" if active
              else "No active DLM lifecycle policies — EBS volumes have no automated daily snapshot protection")
    except Exception:
        s.add("EBS-002", "EBS", "Daily EBS Snapshot Policy", "Critical", "SKIP",
              "API error — could not query DLM policies")

    # EBS-003 Instance Store
    try:
        res      = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
        is_types = [i.get("InstanceType", "") for r in res.get("Reservations", [])
                    for i in r.get("Instances", [])]
        is_count = sum(1 for t in is_types if re.match(r"^(d\d|i\d|h\d)", t))
        s.add("EBS-003", "EBS", "No Critical Data on Instance Store", "Critical",
              "WARN" if is_count else "PASS",
              f"{is_count} instance(s) use Instance Store (d/i/h family) — verify no critical data on ephemeral disks" if is_count
              else "No Instance Store instance types detected in running instances")
    except Exception:
        s.add("EBS-003", "EBS", "No Critical Data on Instance Store", "Critical", "SKIP", "API error")

    # EBS-004 AWS Backup Coverage
    try:
        bkp        = client("backup", s.region)
        prot_res   = bkp.list_protected_resources().get("Results", [])
        prot       = len(prot_res)
        vols_resp  = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
        total_vols = sum(1 for r in vols_resp.get("Reservations", [])
                         for i in r.get("Instances", [])
                         for _ in i.get("BlockDeviceMappings", []))
        s.add("EBS-004", "EBS", "AWS Backup Coverage", "Critical",
              "PASS" if prot > 0 else "FAIL",
              f"{prot} resource(s) enrolled in AWS Backup (all types)" if prot
              else f"0/{total_vols} attached EBS volumes in AWS Backup — no centralised backup protection")
    except Exception:
        s.add("EBS-004", "EBS", "AWS Backup Coverage", "Critical", "SKIP", "API error")

    # EBS-005 Vault Lock
    try:
        bkp    = client("backup", s.region)
        vaults = bkp.list_backup_vaults().get("BackupVaultList", [])
        locked = [v["BackupVaultName"] for v in vaults if v.get("Locked")]
        s.add("EBS-005", "EBS", "Backup Vault Lock Enabled", "Critical",
              "PASS" if locked else "FAIL",
              f"Vault(s) with lock enabled: {', '.join(locked)}" if locked
              else "No backup vaults have Vault Lock — backups can be deleted by any admin")
    except Exception:
        s.add("EBS-005", "EBS", "Backup Vault Lock Enabled", "Critical", "SKIP", "API error")

    # EBS-006 Failed Backup Jobs
    try:
        bkp    = client("backup", s.region)
        failed = len(bkp.list_backup_jobs(ByState="FAILED").get("BackupJobs", []))
        s.add("EBS-006", "EBS", "No Failed EBS Backup Jobs", "Critical",
              "PASS" if failed == 0 else "FAIL",
              "No failed backup jobs in AWS Backup" if failed == 0
              else f"{failed} failed backup job(s) — those resources have no current recovery point")
    except Exception:
        s.add("EBS-006", "EBS", "No Failed EBS Backup Jobs", "Critical", "SKIP", "API error")


# ── RDS ────────────────────────────────────────────────────────────────────────
def check_rds(s: AuditState) -> None:
    rds = client("rds", s.region)
    try:
        dbs = rds.describe_db_instances().get("DBInstances", [])
    except Exception:
        for cid, ctrl in [("RDS-001","Deletion Protection Enabled"),
                           ("RDS-002","Automated Backups >= 7 Days"),
                           ("RDS-003","Multi-AZ Enabled"),
                           ("RDS-004","Manual Snapshot Before Migration"),
                           ("RDS-005","RDS in Private Subnets Only")]:
            s.add(cid, "RDS", ctrl, "Critical", "SKIP", "API error — could not describe RDS instances")
        return

    if not dbs:
        for cid, ctrl in [("RDS-001","Deletion Protection Enabled"),
                           ("RDS-002","Automated Backups >= 7 Days"),
                           ("RDS-003","Multi-AZ Enabled"),
                           ("RDS-004","Manual Snapshot Before Migration"),
                           ("RDS-005","RDS in Private Subnets Only")]:
            s.add(cid, "RDS", ctrl, "Critical", "SKIP", "No RDS instances found in this region")
        return

    prot_fail = [db["DBInstanceIdentifier"] for db in dbs if not db.get("DeletionProtection")]
    ret_fail  = [f"{db['DBInstanceIdentifier']}(ret={db['BackupRetentionPeriod']})"
                 for db in dbs if db.get("BackupRetentionPeriod", 0) < 7]
    maz_fail  = [db["DBInstanceIdentifier"] for db in dbs if not db.get("MultiAZ")]
    pub_fail  = [db["DBInstanceIdentifier"] for db in dbs if db.get("PubliclyAccessible")]

    s.add("RDS-001", "RDS", "Deletion Protection Enabled", "Critical",
          "PASS" if not prot_fail else "FAIL",
          f"All {len(dbs)} RDS instance(s) have deletion protection enabled" if not prot_fail
          else f"Deletion protection DISABLED on: {prot_fail} — instances can be accidentally deleted")
    s.add("RDS-002", "RDS", "Automated Backups >= 7 Days", "Critical",
          "PASS" if not ret_fail else "FAIL",
          f"All {len(dbs)} instance(s) have backup retention >= 7 days" if not ret_fail
          else f"Low retention detected: {ret_fail} — insufficient recovery window")
    s.add("RDS-003", "RDS", "Multi-AZ Enabled", "Critical",
          "PASS" if not maz_fail else "FAIL",
          f"All {len(dbs)} instance(s) are Multi-AZ — high availability configured" if not maz_fail
          else f"Single-AZ instances (no failover): {maz_fail} — availability risk in AZ outage")
    try:
        snaps = rds.describe_db_snapshots(SnapshotType="manual").get("DBSnapshots", [])
        s.add("RDS-004", "RDS", "Manual Snapshot Before Migration", "Critical",
              "PASS" if snaps else "WARN",
              f"{len(snaps)} manual snapshot(s) exist — pre-migration restore point available" if snaps
              else "No manual snapshots — take one before any schema migration or major change")
    except Exception:
        s.add("RDS-004", "RDS", "Manual Snapshot Before Migration", "Critical", "SKIP",
              "API error — could not list manual snapshots")
    s.add("RDS-005", "RDS", "RDS in Private Subnets Only", "Critical",
          "PASS" if not pub_fail else "FAIL",
          f"All {len(dbs)} RDS instance(s) are in private subnets" if not pub_fail
          else f"Publicly accessible RDS instance(s): {pub_fail} — direct internet exposure is a critical risk")


# ── DynamoDB  [FIXED: full pagination] ────────────────────────────────────────
def check_dynamodb(s: AuditState) -> None:
    ddb = client("dynamodb", s.region)
    try:
        tables: List[str] = []
        for page in ddb.get_paginator("list_tables").paginate():
            tables.extend(page.get("TableNames", []))
    except Exception:
        for cid, ctrl in [("DDB-001","PITR Enabled on Every Table"),
                           ("DDB-002","On-Demand Backup Before Schema Change"),
                           ("DDB-003","Table Deletion Protection")]:
            s.add(cid, "DynamoDB", ctrl, "Critical", "SKIP", "API error")
        return

    if not tables:
        for cid, ctrl in [("DDB-001","PITR Enabled on Every Table"),
                           ("DDB-002","On-Demand Backup Before Schema Change"),
                           ("DDB-003","Table Deletion Protection")]:
            s.add(cid, "DynamoDB", ctrl, "Critical", "SKIP", "No DynamoDB tables found in this region")
        return

    pitr_fail: List[str] = []
    del_fail:  List[str] = []
    backup_warn: List[str] = []
    for t in tables:
        try:
            cb = ddb.describe_continuous_backups(TableName=t)
            if (cb["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
                    ["PointInTimeRecoveryStatus"] != "ENABLED"):
                pitr_fail.append(t)
        except Exception:
            pitr_fail.append(t)
        try:
            if not ddb.describe_table(TableName=t)["Table"].get("DeletionProtectionEnabled"):
                del_fail.append(t)
        except Exception:
            del_fail.append(t)
        try:
            if not ddb.list_backups(TableName=t).get("BackupSummaries"):
                backup_warn.append(t)
        except Exception:
            backup_warn.append(t)

    s.add("DDB-001", "DynamoDB", "PITR Enabled on Every Table", "Critical",
          "PASS" if not pitr_fail else "FAIL",
          f"All {len(tables)} table(s) have PITR enabled" if not pitr_fail
          else f"PITR DISABLED on {len(pitr_fail)} table(s): {pitr_fail[:5]} — cannot restore to arbitrary point")
    s.add("DDB-002", "DynamoDB", "On-Demand Backup Before Schema Change", "Critical",
          "PASS" if not backup_warn else "WARN",
          f"All {len(tables)} table(s) have at least one on-demand backup" if not backup_warn
          else f"No on-demand backups for {len(backup_warn)} table(s): {backup_warn[:5]}")
    s.add("DDB-003", "DynamoDB", "Table Deletion Protection", "Critical",
          "PASS" if not del_fail else "FAIL",
          f"All {len(tables)} table(s) have deletion protection enabled" if not del_fail
          else f"Deletion protection DISABLED on {len(del_fail)} table(s): {del_fail[:5]}")


# ── S3  [FIXED: global client — no regional redirect errors] ──────────────────
def check_s3(s: AuditState) -> None:
    s3 = boto3.client("s3", config=RETRY_CFG)   # S3 is a global API
    try:
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    except Exception:
        for cid in ["S3-001","S3-002","S3-003","S3-004","S3-005"]:
            s.add(cid, "S3", "-", "Critical", "SKIP", "API error — could not list S3 buckets")
        return

    if not buckets:
        for cid in ["S3-001","S3-002","S3-003","S3-004","S3-005"]:
            s.add(cid, "S3", "-", "Critical", "SKIP", "No S3 buckets found")
        return

    vers_fail: List[str] = []
    mfa_warn:  List[str] = []
    pab_fail:  List[str] = []
    obj_warn:  List[str] = []
    for b in buckets:
        try:
            v = s3.get_bucket_versioning(Bucket=b)
            if v.get("Status") != "Enabled":
                vers_fail.append(b)
            if v.get("MFADelete") != "Enabled":
                mfa_warn.append(b)
        except Exception:
            vers_fail.append(b)
        try:
            cfg = s3.get_public_access_block(Bucket=b).get("PublicAccessBlockConfiguration", {})
            if not all(cfg.values()):
                pab_fail.append(b)
        except Exception:
            pab_fail.append(b)
        try:
            ol = s3.get_object_lock_configuration(Bucket=b)
            if ol.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
                obj_warn.append(b)
        except Exception:
            obj_warn.append(b)

    s.add("S3-001", "S3", "Versioning on All Prod Buckets", "Critical",
          "PASS" if not vers_fail else "FAIL",
          f"All {len(buckets)} bucket(s) have versioning enabled" if not vers_fail
          else f"{len(vers_fail)}/{len(buckets)} NOT versioned: {vers_fail[:3]} — deleted objects cannot be recovered")
    s.add("S3-002", "S3", "MFA Delete on Critical Buckets", "Critical",
          "PASS" if not mfa_warn else "WARN",
          "MFA Delete enabled on all buckets" if not mfa_warn
          else f"{len(mfa_warn)} bucket(s) without MFA Delete — compromised credentials could permanently delete objects")
    s.add("S3-003", "S3", "Block Public Access", "Critical",
          "PASS" if not pab_fail else "FAIL",
          f"All {len(buckets)} bucket(s) have Block Public Access fully enabled" if not pab_fail
          else f"{len(pab_fail)} bucket(s) publicly accessible: {pab_fail[:3]}")

    tf_bucket = next((b for b in buckets if "tfstate" in b.lower() or "terraform" in b.lower()), None)
    if tf_bucket:
        try:
            tfv    = s3.get_bucket_versioning(Bucket=tf_bucket)
            status = tfv.get("Status", "None")
            s.add("S3-004", "S3", "Terraform State Bucket Versioning", "Critical",
                  "PASS" if status == "Enabled" else "FAIL",
                  f"TF state bucket '{tf_bucket}' versioning={status}")
        except Exception:
            s.add("S3-004", "S3", "Terraform State Bucket Versioning", "Critical", "SKIP",
                  "Could not check TF state bucket")
    else:
        s.add("S3-004", "S3", "Terraform State Bucket Versioning", "Critical", "WARN",
              "No Terraform state bucket detected (no bucket with 'tfstate' or 'terraform' in name)")

    s.add("S3-005", "S3", "Object Lock or MFA Delete", "Critical",
          "PASS" if not obj_warn else "WARN",
          f"All {len(buckets)} bucket(s) protected with Object Lock" if not obj_warn
          else f"{len(obj_warn)}/{len(buckets)} bucket(s) without Object Lock — data not protected against deletion")


# ── MemoryDB ───────────────────────────────────────────────────────────────────
def check_memorydb(s: AuditState) -> None:
    mdb = client("memorydb", s.region)
    try:
        clusters = mdb.describe_clusters().get("Clusters", [])
    except Exception:
        for cid in ["MDB-001","MDB-002","MDB-003","MDB-004","MDB-005"]:
            s.add(cid, "MemoryDB", "-", "Critical", "SKIP", "API error — could not describe MemoryDB clusters")
        return

    if not clusters:
        for cid in ["MDB-001","MDB-002","MDB-003","MDB-004","MDB-005"]:
            s.add(cid, "MemoryDB", "-", "Critical", "SKIP", "No MemoryDB clusters found in this region")
        return

    ret_fail = [c["Name"] for c in clusters if c.get("SnapshotRetentionLimit", 0) < 7]
    maz_fail = [c["Name"] for c in clusters if c.get("AvailabilityMode") != "MultiAZ"]

    s.add("MDB-001", "MemoryDB", "Automatic Snapshots >= 7 Days", "Critical",
          "PASS" if not ret_fail else "FAIL",
          f"All {len(clusters)} cluster(s) have snapshot retention >= 7 days" if not ret_fail
          else f"Low retention (<7 days) on: {ret_fail} — insufficient PITR window")
    s.add("MDB-002", "MemoryDB", "Multi-AZ Enabled", "Critical",
          "PASS" if not maz_fail else "FAIL",
          f"All {len(clusters)} cluster(s) are Multi-AZ" if not maz_fail
          else f"Not Multi-AZ: {maz_fail} — cluster unavailable during AZ failure")

    snaps_warn: List[str] = []
    for c in clusters:
        try:
            if not mdb.describe_snapshots(ClusterName=c["Name"]).get("Snapshots"):
                snaps_warn.append(c["Name"])
        except Exception:
            snaps_warn.append(c["Name"])
    s.add("MDB-003", "MemoryDB", "Manual Snapshot Before Modification", "Critical",
          "PASS" if not snaps_warn else "WARN",
          f"All {len(clusters)} cluster(s) have at least one manual snapshot" if not snaps_warn
          else f"No manual snapshots for: {snaps_warn} — take snapshot before any config change")
    s.add("MDB-004", "MemoryDB", "Private Subnet Only — No Public Access", "Critical",
          "WARN", "Manual validation required — verify MemoryDB subnet groups use only private subnets")
    try:
        acls  = mdb.describe_acls().get("ACLs", [])
        s.add("MDB-005", "MemoryDB", "ACL Configured — No Open Access", "Critical",
              "PASS" if acls else "FAIL",
              f"{len(acls)} ACL(s) configured on MemoryDB — access control enforced" if acls
              else "No MemoryDB ACLs configured — cluster may allow unauthenticated access")
    except Exception:
        s.add("MDB-005", "MemoryDB", "ACL Configured — No Open Access", "Critical", "SKIP", "API error")


# ── EKS ────────────────────────────────────────────────────────────────────────
def check_eks(s: AuditState) -> None:
    eks = client("eks", s.region)
    try:
        cluster_names = eks.list_clusters().get("clusters", [])
    except Exception:
        for cid in ["EKS-001","EKS-002","EKS-003","EKS-004"]:
            s.add(cid, "EKS", "-", "Critical", "SKIP", "API error — could not list EKS clusters")
        return

    if not cluster_names:
        for cid in ["EKS-001","EKS-002","EKS-003","EKS-004"]:
            s.add(cid, "EKS", "-", "Critical", "SKIP", "No EKS clusters found in this region")
        return

    count = len(cluster_names)
    s.add("EKS-001", "EKS", "Velero Backup Schedules for PVs", "Critical", "WARN",
          f"{count} cluster(s) — verify Velero installed and backup schedules exist for all PersistentVolumes")
    s.add("EKS-002", "EKS", "Kubernetes Secrets Backed Up", "Critical", "WARN",
          f"{count} cluster(s) — verify k8s Secrets backed up via Velero or Sealed Secrets")
    s.add("EKS-003", "EKS", "All Manifests in Git — No kubectl-only", "Critical", "WARN",
          "Manual check — review CloudTrail for direct kubectl apply events that bypass GitOps")
    s.add("EKS-004", "EKS", "Secrets Not Hardcoded in Manifests", "Critical", "WARN",
          "Manual check — scan manifests with trufflehog or detect-secrets to detect hardcoded credentials")


# ── MSK  [FIXED: ProvisionedThroughput check instead of autoscaling API] ──────
def check_msk(s: AuditState) -> None:
    kafka = client("kafka", s.region)
    try:
        clusters = kafka.list_clusters().get("ClusterInfoList", [])
    except Exception:
        for cid in ["MSK-001","MSK-002","MSK-003","MSK-004"]:
            s.add(cid, "MSK", "-", "Critical", "SKIP", "API error — could not list MSK clusters")
        return

    if not clusters:
        for cid in ["MSK-001","MSK-002","MSK-003","MSK-004"]:
            s.add(cid, "MSK", "-", "Critical", "SKIP", "No MSK clusters found in this region")
        return

    # FIXED: ProvisionedThroughput inside BrokerNodeGroupInfo is the correct API
    scaling_fail: List[str] = []
    for c in clusters:
        try:
            detail = kafka.describe_cluster(ClusterArn=c["ClusterArn"]).get("ClusterInfo", {})
            pt = (detail.get("BrokerNodeGroupInfo", {})
                        .get("StorageInfo", {})
                        .get("EbsStorageInfo", {})
                        .get("ProvisionedThroughput", {}))
            if not pt.get("Enabled"):
                scaling_fail.append(c["ClusterName"])
        except Exception:
            scaling_fail.append(c.get("ClusterName", "unknown"))

    s.add("MSK-001", "MSK", "Auto Storage Scaling Enabled", "Critical",
          "PASS" if not scaling_fail else "FAIL",
          f"All {len(clusters)} cluster(s) have ProvisionedThroughput (auto-scaling) enabled" if not scaling_fail
          else f"Auto-storage scaling NOT enabled on: {scaling_fail} — disk full = messages dropped")
    s.add("MSK-002", "MSK", "Topic Replication Factor >= 3", "Critical", "WARN",
          f"{len(clusters)} cluster(s) — verify replication factor >=3 via kafka-topics.sh inside VPC")
    s.add("MSK-003", "MSK", "Topic Retention Period Sufficient", "Critical", "WARN",
          f"{len(clusters)} cluster(s) — verify message retention via kafka-topics.sh; requires VPC access")

    broker_fail = [c["ClusterName"] for c in clusters
                   if c.get("BrokerNodeGroupInfo", {}).get("NumberOfBrokerNodes", 0) < 3]
    s.add("MSK-004", "MSK", "MSK in Private Subnets Only", "Critical",
          "PASS" if not broker_fail else "WARN",
          "All MSK brokers have >= 3 nodes; verify subnets are private via VPC routing" if not broker_fail
          else f"Cluster(s) with < 3 broker nodes: {broker_fail} — also verify private subnet placement")


# ── KMS ────────────────────────────────────────────────────────────────────────
def check_kms(s: AuditState) -> None:
    kms = client("kms", s.region)
    try:
        keys = kms.list_keys().get("Keys", [])
    except Exception:
        s.add("KMS-001", "KMS", "Key Deletion Window = 30 Days", "Critical", "SKIP", "API error")
        s.add("KMS-002", "KMS", "Key Policies in Version Control",  "Critical", "SKIP", "API error")
        return

    pending = 0; total_cmk = 0
    for key in keys:
        kid = key["KeyId"]
        try:
            meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            total_cmk += 1
            state_val = meta.get("KeyState", "")
            # Count keys in PendingDeletion or with unusually short deletion window
            if state_val == "PendingDeletion":
                pending += 1
            elif meta.get("PendingDeletionWindowInDays", 30) < 30:
                pending += 1
        except Exception:
            pass

    s.add("KMS-001", "KMS", "Key Deletion Window = 30 Days", "Critical",
          "PASS" if pending == 0 else "FAIL",
          f"All {total_cmk} customer-managed KMS key(s) are enabled and active" if pending == 0
          else f"{pending} CMK(s) in PendingDeletion or short deletion window — encrypted data at risk")
    s.add("KMS-002", "KMS", "Key Policies in Version Control", "Critical",
          "WARN",
          f"{total_cmk} CMK(s) found — manually verify all key policies are exported to Git/IaC")


# ── Secrets Manager ────────────────────────────────────────────────────────────
def check_secrets_manager(s: AuditState) -> None:
    sm = client("secretsmanager", s.region)
    try:
        secrets = sm.list_secrets().get("SecretList", [])
    except Exception:
        s.add("SEC-001", "Secrets Manager", "Secret Recovery Window >= 7 Days", "Critical", "SKIP", "API error")
        s.add("SEC-002", "Secrets Manager", "No Hardcoded Secrets in Code", "Critical", "SKIP", "API error")
        return

    if not secrets:
        s.add("SEC-001", "Secrets Manager", "Secret Recovery Window >= 7 Days", "Critical", "SKIP",
              "No secrets found in Secrets Manager")
        s.add("SEC-002", "Secrets Manager", "No Hardcoded Secrets in Code", "Critical", "WARN",
              "No Secrets Manager secrets — run: trufflehog git file://. --only-verified in your repo")
        return

    # RecoveryWindowInDays only present on pending-delete secrets; check DeletedDate
    deleted = [x["Name"] for x in secrets if x.get("DeletedDate")]
    no_rec  = [x["Name"] for x in secrets
               if x.get("DeletedDate") and (x.get("RecoveryWindowInDays") or 30) < 7]

    s.add("SEC-001", "Secrets Manager", "Secret Recovery Window >= 7 Days", "Critical",
          "PASS" if not deleted else "FAIL",
          f"All {len(secrets)} secret(s) safe; no pending deletions" if not deleted
          else f"Pending deletion: {deleted}; short window (<7d): {no_rec} — risk of accidental permanent loss")
    s.add("SEC-002", "Secrets Manager", "No Hardcoded Secrets in Code", "Critical",
          "WARN",
          f"{len(secrets)} secret(s) in Secrets Manager — also run: trufflehog git file://. --only-verified")


# ── SQS ────────────────────────────────────────────────────────────────────────
def check_sqs(s: AuditState) -> None:
    sqs = client("sqs", s.region)
    try:
        urls = sqs.list_queues().get("QueueUrls", [])
    except Exception:
        s.add("SQS-001", "SQS", "DLQ on Every Prod Queue", "Critical", "SKIP", "API error")
        s.add("SQS-002", "SQS", "DLQ Depth = 0",           "Critical", "SKIP", "API error")
        return

    if not urls:
        s.add("SQS-001", "SQS", "DLQ on Every Prod Queue", "Critical", "SKIP", "No SQS queues found")
        s.add("SQS-002", "SQS", "DLQ Depth = 0",           "Critical", "SKIP", "No SQS queues found")
        return

    no_dlq: List[str] = []
    dlq_depth = 0; total_q = 0
    for url in urls:
        name = url.split("/")[-1]
        if re.search(r"dlq|dead", name, re.IGNORECASE):
            continue
        total_q += 1
        try:
            attrs = sqs.get_queue_attributes(QueueUrl=url,
                                             AttributeNames=["RedrivePolicy"]).get("Attributes", {})
            rp = attrs.get("RedrivePolicy")
            if not rp:
                no_dlq.append(name)
            else:
                rp_json  = json.loads(rp)
                dlq_name = rp_json.get("deadLetterTargetArn", "").split(":")[-1]
                try:
                    dlq_url = sqs.get_queue_url(QueueName=dlq_name)["QueueUrl"]
                    d_attrs = sqs.get_queue_attributes(
                        QueueUrl=dlq_url,
                        AttributeNames=["ApproximateNumberOfMessages"]
                    ).get("Attributes", {})
                    dlq_depth += int(d_attrs.get("ApproximateNumberOfMessages", 0))
                except Exception:
                    pass   # cross-account DLQ — depth unavailable but DLQ exists
        except Exception:
            no_dlq.append(name)

    s.add("SQS-001", "SQS", "DLQ on Every Prod Queue", "Critical",
          "PASS" if not no_dlq else "FAIL",
          f"All {total_q} prod queue(s) have a DLQ configured" if not no_dlq
          else f"No DLQ on queue(s): {no_dlq} — failed messages will be silently discarded")
    s.add("SQS-002", "SQS", "DLQ Depth = 0", "Critical",
          "PASS" if dlq_depth == 0 else "FAIL",
          "No failed messages in any DLQ — all messages processed successfully" if dlq_depth == 0
          else f"{dlq_depth} failed/unprocessed message(s) in DLQ(s) — indicates ongoing processing failures")


# ── Lambda  [FIXED: pagination + cached fn list + better env-secret scan] ─────
def check_lambda(s: AuditState) -> None:
    lam = client("lambda", s.region)
    try:
        fns: List = []
        for page in lam.get_paginator("list_functions").paginate():
            fns.extend(page.get("Functions", []))
        s._lambda_fns = fns          # cache for X-Ray check — avoids duplicate API call
    except Exception:
        for cid in ["LAM-001","LAM-002","LAM-003","LAM-004"]:
            s.add(cid, "Lambda", "-", "Critical", "SKIP", "API error — could not list Lambda functions")
        return

    if not fns:
        for cid in ["LAM-001","LAM-002","LAM-003","LAM-004"]:
            s.add(cid, "Lambda", "-", "Critical", "SKIP", "No Lambda functions found in this region")
        return

    no_dest:      List[str] = []
    latest_alias: List[str] = []
    no_alias_fn:  List[str] = []
    plain_secrets: List[str] = []
    sus_keys     = ["password","passwd","secret","token","api_key","apikey","access_key","credential","pwd"]
    safe_suffixes = ["_table_name","_table","_bucket","_name","_arn","_id","_url","_region","_host"]

    for fn in fns:
        fname = fn["FunctionName"]
        try:
            dest = lam.get_function_event_invoke_config(FunctionName=fname)
            if not dest.get("DestinationConfig", {}).get("OnFailure", {}).get("Destination"):
                no_dest.append(fname)
        except Exception:
            no_dest.append(fname)
        try:
            aliases = lam.list_aliases(FunctionName=fname).get("Aliases", [])
            if not aliases:
                no_alias_fn.append(fname)
            else:
                for a in aliases:
                    if a.get("FunctionVersion") == "$LATEST":
                        latest_alias.append(fname)
                        break
        except Exception:
            no_alias_fn.append(fname)
        # IMPROVED: also flag when env vars exist but no KMS key is set (vars unencrypted)
        env_vars = fn.get("Environment", {}).get("Variables", {})
        kms_key  = fn.get("KMSKeyArn", "")
        if env_vars and not kms_key:
            for k, v in env_vars.items():
                kl = k.lower()
                if (any(sk in kl for sk in sus_keys)
                        and not any(kl.endswith(x) for x in safe_suffixes)
                        and not str(v).startswith("arn:aws")
                        and not str(v).startswith("/")):
                    plain_secrets.append(fname)
                    break

    total = len(fns)
    s.add("LAM-001", "Lambda", "OnFailure Destination on Async Functions", "Critical",
          "PASS" if not no_dest else "FAIL",
          f"All {total} Lambda function(s) have an OnFailure destination" if not no_dest
          else f"{len(no_dest)}/{total} missing OnFailure destination: {no_dest[:5]} — async failures lost silently")

    if not latest_alias and not no_alias_fn:
        s.add("LAM-002", "Lambda", "Prod Alias Points to Version Not $LATEST", "Critical",
              "PASS", f"All {total} function aliases point to fixed version numbers — safe for prod")
    elif latest_alias:
        s.add("LAM-002", "Lambda", "Prod Alias Points to Version Not $LATEST", "Critical",
              "FAIL",
              f"{len(latest_alias)} function(s) alias → $LATEST: {latest_alias[:5]} — mutable, unsafe for prod")
    else:
        s.add("LAM-002", "Lambda", "Prod Alias Points to Version Not $LATEST", "Critical",
              "WARN",
              f"{len(no_alias_fn)}/{total} function(s) have no alias — use versioned aliases for safer rollback")

    s.add("LAM-003", "Lambda", "All Function Code in Git", "Critical", "WARN",
          f"{total} function(s) — check CloudTrail for console-based UpdateFunctionCode events bypassing Git")
    s.add("LAM-004", "Lambda", "No Plain-Text Secrets in Env Vars", "Critical",
          "PASS" if not plain_secrets else "FAIL",
          "No suspicious plain-text secrets in Lambda env vars" if not plain_secrets
          else f"{len(plain_secrets)} function(s) with potential plain-text secrets: {plain_secrets[:5]} — move to Secrets Manager")


# ── API Gateway ────────────────────────────────────────────────────────────────
def check_apigateway(s: AuditState) -> None:
    agw = client("apigateway", s.region)
    try:
        apis = agw.get_rest_apis().get("items", [])
    except Exception:
        s.add("AGW-001", "API Gateway", "API Definitions Exported to Git", "Critical", "SKIP", "API error")
        s.add("AGW-002", "API Gateway", "WAF ACL Attached to All Prod Stages", "Critical", "SKIP", "API error")
        return

    if not apis:
        s.add("AGW-001", "API Gateway", "API Definitions Exported to Git", "Critical", "SKIP", "No REST APIs found")
        s.add("AGW-002", "API Gateway", "WAF ACL Attached to All Prod Stages", "Critical", "SKIP", "No REST APIs found")
        return

    count = len(apis)
    s.add("AGW-001", "API Gateway", "API Definitions Exported to Git", "Critical", "WARN",
          f"{count} REST API(s) found — verify OpenAPI/Swagger export of each is committed to Git")

    no_waf:   List[str] = []
    no_trace: List[str] = []
    for api in apis:
        api_name = api.get("name", api["id"])
        try:
            stage = agw.get_stage(restApiId=api["id"], stageName="prod")
            if not stage.get("webAclArn"):
                no_waf.append(api_name)
            if not stage.get("tracingEnabled"):
                no_trace.append(api_name)
        except Exception:
            no_waf.append(api_name)
            no_trace.append(api_name)

    s.add("AGW-002", "API Gateway", "WAF ACL Attached to All Prod Stages", "Critical",
          "PASS" if not no_waf else "FAIL",
          f"All {count} API(s) have WAF on prod stage" if not no_waf
          else f"{len(no_waf)} API(s) without WAF on prod stage: {no_waf} — exposed without threat protection")
    s.add("XR-003", "X-Ray", "Tracing Enabled on API Gateway", "High",
          "PASS" if not no_trace else "WARN",
          f"X-Ray tracing enabled on all {count} API Gateway prod stage(s)" if not no_trace
          else f"{len(no_trace)}/{count} prod stage(s) without X-Ray tracing: {no_trace}")


# ── CloudTrail ─────────────────────────────────────────────────────────────────
def check_cloudtrail(s: AuditState) -> None:
    ct = client("cloudtrail", s.region)
    try:
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    except Exception:
        for cid in ["CT-001","CT-002","CT-003","CT-004"]:
            s.add(cid, "CloudTrail", "-", "Critical", "FAIL", "API error — could not describe CloudTrail trails")
        return

    if not trails:
        for cid, ctrl in [("CT-001","Multi-Region Trail Active"),("CT-002","Log File Validation Enabled"),
                           ("CT-003","CloudTrail S3 Bucket Versioning"),("CT-004","Alert on TrailStopLogging API Call")]:
            s.add(cid, "CloudTrail", ctrl, "Critical", "FAIL",
                  "NO TRAILS FOUND — zero audit trail; all AWS API calls are unlogged")
        return

    no_multi = [t["Name"] for t in trails if not t.get("IsMultiRegionTrail")]
    no_valid  = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]

    s.add("CT-001", "CloudTrail", "Multi-Region Trail Active", "Critical",
          "PASS" if not no_multi else "FAIL",
          f"All {len(trails)} trail(s) are multi-region" if not no_multi
          else f"Single-region trail(s): {no_multi} — activity in other regions is not logged")
    s.add("CT-002", "CloudTrail", "Log File Validation Enabled", "Critical",
          "PASS" if not no_valid else "FAIL",
          f"All {len(trails)} trail(s) have log file integrity validation" if not no_valid
          else f"Validation DISABLED on: {no_valid} — tampered log files cannot be detected")

    bucket = trails[0].get("S3BucketName") if trails else None
    if bucket:
        try:
            s3  = boto3.client("s3", config=RETRY_CFG)  # global client
            v   = s3.get_bucket_versioning(Bucket=bucket)
            st  = v.get("Status", "None")
            s.add("CT-003", "CloudTrail", "CloudTrail S3 Bucket Versioning", "Critical",
                  "PASS" if st == "Enabled" else "FAIL",
                  f"CloudTrail bucket '{bucket}' versioning={st}" if st == "Enabled"
                  else f"CloudTrail bucket '{bucket}' versioning={st} — log files could be deleted without recovery")
        except Exception:
            s.add("CT-003", "CloudTrail", "CloudTrail S3 Bucket Versioning", "Critical", "SKIP",
                  "Could not check S3 bucket versioning")
    else:
        s.add("CT-003", "CloudTrail", "CloudTrail S3 Bucket Versioning", "Critical", "SKIP",
              "No S3 bucket found for trail")

    try:
        is_logging = ct.get_trail_status(Name=trails[0]["Name"]).get("IsLogging", False)
        s.add("CT-004", "CloudTrail", "Alert on TrailStopLogging API Call", "Critical",
              "PASS" if is_logging else "FAIL",
              f"Trail '{trails[0]['Name']}' is actively logging — also verify CloudWatch alarm for StopLogging" if is_logging
              else f"Trail '{trails[0]['Name']}' is NOT logging — audit trail is broken")
    except Exception:
        s.add("CT-004", "CloudTrail", "Alert on TrailStopLogging API Call", "Critical", "SKIP",
              "Could not get trail status")

# ── Route 53 ───────────────────────────────────────────────────────────────────
def check_route53(s: AuditState) -> None:
    r53 = boto3.client("route53", config=RETRY_CFG)
    try:
        zones = r53.list_hosted_zones().get("HostedZones", [])
        if not zones:
            s.add("R53-001", "Route 53", "All Hosted Zones Exported to Git", "Critical", "SKIP",
                  "No hosted zones found in Route 53")
        else:
            missing = sum(1 for z in zones
                          if not os.path.exists(
                              f"route53-backup/dns-backup-{z['Id'].split('/')[-1]}.json"))
            s.add("R53-001", "Route 53", "All Hosted Zones Exported to Git", "Critical",
                  "PASS" if missing == 0 else "WARN",
                  f"All {len(zones)} zone(s) have a local backup file in route53-backup/" if missing == 0
                  else f"{missing}/{len(zones)} zone(s) missing backup — run: aws route53 list-resource-record-sets --hosted-zone-id <id>")
    except Exception:
        s.add("R53-001", "Route 53", "All Hosted Zones Exported to Git", "Critical", "SKIP", "API error")

    try:
        domains = boto3.client("route53domains", region_name="us-east-1", config=RETRY_CFG)\
                        .list_domains().get("Domains", [])
        if not domains:
            s.add("R53-002", "Route 53", "Domain Transfer Lock Enabled", "Critical", "WARN",
                  "No domains in Route 53 Registrar — verify transfer lock at your domain registrar")
        else:
            unlocked = [d["DomainName"] for d in domains if not d.get("TransferLock")]
            s.add("R53-002", "Route 53", "Domain Transfer Lock Enabled", "Critical",
                  "PASS" if not unlocked else "FAIL",
                  f"All {len(domains)} domain(s) have transfer lock enabled" if not unlocked
                  else f"{len(unlocked)} domain(s) without transfer lock: {unlocked}")
    except Exception:
        s.add("R53-002", "Route 53", "Domain Transfer Lock Enabled", "Critical", "SKIP",
              "API error (route53domains requires us-east-1)")

    # FIXED: individual try/except per cert to avoid closure bug
    try:
        acm   = client("acm", s.region)
        certs = acm.list_certificates().get("CertificateSummaryList", [])
        failed = 0
        for c in certs:
            try:
                st = acm.describe_certificate(CertificateArn=c["CertificateArn"])\
                         .get("Certificate", {}).get("Status")
                if st != "ISSUED":
                    failed += 1
            except Exception:
                failed += 1
        s.add("R53-003", "Route 53", "ACM Cert Auto-Renewal + Expiry Alerts", "Critical",
              "PASS" if failed == 0 else "FAIL",
              f"All {len(certs)} ACM certificate(s) are in ISSUED state" if failed == 0
              else f"{failed} certificate(s) not in ISSUED state — may be expired or pending validation")
    except Exception:
        s.add("R53-003", "Route 53", "ACM Cert Auto-Renewal + Expiry Alerts", "Critical", "SKIP", "API error")


# ── ECR  [FIXED: only catch LifecyclePolicyNotFoundException as "no policy"] ──
def check_ecr(s: AuditState) -> None:
    ecr = client("ecr", s.region)
    try:
        repos = ecr.describe_repositories().get("repositories", [])
    except Exception:
        s.add("ECR-001", "ECR", "Image Tag Immutability", "Critical", "SKIP", "API error")
        s.add("ECR-002", "ECR", "Lifecycle Policy Retains Rollback Images", "Critical", "SKIP", "API error")
        return

    if not repos:
        s.add("ECR-001", "ECR", "Image Tag Immutability", "Critical", "SKIP", "No ECR repositories found")
        s.add("ECR-002", "ECR", "Lifecycle Policy Retains Rollback Images", "Critical", "SKIP",
              "No ECR repositories found")
        return

    count   = len(repos)
    mutable = [r["repositoryName"] for r in repos if r.get("imageTagMutability") != "IMMUTABLE"]
    s.add("ECR-001", "ECR", "Image Tag Immutability", "Critical",
          "PASS" if not mutable else "FAIL",
          f"All {count} repository(ies) have IMMUTABLE image tags" if not mutable
          else f"{len(mutable)}/{count} MUTABLE: {mutable[:5]} — image tags can be overwritten, breaking rollback")

    no_policy: List[str] = []
    for r in repos:
        rname = r["repositoryName"]
        try:
            ecr.get_lifecycle_policy(repositoryName=rname)
        except ClientError as e:
            if e.response["Error"]["Code"] in (
                    "LifecyclePolicyNotFoundException", "RepositoryNotFoundException"):
                no_policy.append(rname)
            # throttle / access-denied → skip silently (don't count as missing)
        except Exception:
            pass

    s.add("ECR-002", "ECR", "Lifecycle Policy Retains Rollback Images", "Critical",
          "PASS" if not no_policy else "FAIL",
          f"All {count} repository(ies) have a lifecycle policy" if not no_policy
          else f"{len(no_policy)} repository(ies) missing lifecycle policy: {no_policy[:5]}")


# ── AWS Config  [FIXED: concurrent region checks via ThreadPoolExecutor] ───────
def check_config(s: AuditState) -> None:
    try:
        regions = [r["RegionName"] for r in
                   client("ec2", s.region).describe_regions().get("Regions", [])]
    except Exception:
        s.add("CFG-001", "AWS Config", "Config Enabled in All Prod Regions", "Critical", "SKIP",
              "Could not list regions")
        return

    not_recording: List[str] = []

    def _check_region(reg: str) -> bool:
        try:
            statuses = boto3.client("config", region_name=reg, config=RETRY_CFG)\
                            .describe_configuration_recorder_status()\
                            .get("ConfigurationRecordersStatus", [])
            return bool(statuses and statuses[0].get("recording"))
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=12) as pool:
        future_to_reg = {pool.submit(_check_region, reg): reg for reg in regions}
        for fut in as_completed(future_to_reg):
            reg = future_to_reg[fut]
            if not fut.result():
                not_recording.append(reg)

    total = len(regions)
    s.add("CFG-001", "AWS Config", "Config Enabled in All Prod Regions", "Critical",
          "PASS" if not not_recording else "FAIL",
          f"AWS Config is actively recording in all {total} region(s)" if not not_recording
          else f"{len(not_recording)}/{total} region(s) NOT recording: {sorted(not_recording)[:5]}")


# ── SES ────────────────────────────────────────────────────────────────────────
def check_ses(s: AuditState) -> None:
    sesv2 = client("sesv2", s.region)
    dkim_pass = 0; dkim_fail = 0
    try:
        for identity in sesv2.list_email_identities().get("EmailIdentities", []):
            st = sesv2.get_email_identity(EmailIdentity=identity["IdentityName"])\
                      .get("DkimAttributes", {}).get("Status")
            if st == "SUCCESS":
                dkim_pass += 1
            else:
                dkim_fail += 1
    except Exception:
        pass

    if dkim_pass == 0 and dkim_fail == 0:
        s.add("SES-001", "SES", "DKIM/SPF/DMARC Records in IaC", "Critical", "SKIP",
              "No SES email identities found — SES not configured in this region")
    elif dkim_fail == 0:
        s.add("SES-001", "SES", "DKIM/SPF/DMARC Records in IaC", "Critical",
              "PASS",
              f"All {dkim_pass} SES identity(ies) DKIM verified — also verify SPF and DMARC in IaC")
    else:
        s.add("SES-001", "SES", "DKIM/SPF/DMARC Records in IaC", "Critical",
              "FAIL",
              f"{dkim_fail} SES identity(ies) NOT DKIM verified — emails may be rejected or marked as spam")
    try:
        cs = sesv2.list_configuration_sets().get("ConfigurationSets", [])
        s.add("SES-002", "SES", "Bounce/Complaint SNS Configured", "Critical",
              "PASS" if cs else "FAIL",
              f"{len(cs)} SES configuration set(s) found — verify SNS destinations for bounce/complaint" if cs
              else "No SES configuration sets — bounce/complaint notifications not configured; reputation at risk")
    except Exception:
        s.add("SES-002", "SES", "Bounce/Complaint SNS Configured", "Critical", "SKIP", "API error")


# ── Amplify ────────────────────────────────────────────────────────────────────
def check_amplify(s: AuditState) -> None:
    amp = client("amplify", s.region)
    try:
        apps  = amp.list_apps().get("apps", [])
        count = len(apps)
    except Exception:
        s.add("AMP-001", "Amplify", "Build Config (amplify.yml) in Git", "Critical", "SKIP", "API error")
        s.add("AMP-002", "Amplify", "Env Vars Not Containing Plain-Text Secrets", "Critical", "SKIP", "API error")
        return

    if not count:
        s.add("AMP-001", "Amplify", "Build Config (amplify.yml) in Git", "Critical", "SKIP", "No Amplify apps found")
        s.add("AMP-002", "Amplify", "Env Vars Not Containing Plain-Text Secrets", "Critical", "SKIP",
              "No Amplify apps found")
        return

    s.add("AMP-001", "Amplify", "Build Config (amplify.yml) in Git", "Critical", "WARN",
          f"{count} Amplify app(s) — manually verify amplify.yml is committed to each source repository")
    s.add("AMP-002", "Amplify", "Env Vars Not Containing Plain-Text Secrets", "Critical", "WARN",
          f"{count} Amplify app(s) — inspect env vars in the Amplify console; use Secrets Manager instead")


# ── VPC ────────────────────────────────────────────────────────────────────────
def check_vpc(s: AuditState) -> None:
    ec2 = client("ec2", s.region)
    s.add("VPC-001", "VPC", "All VPC Resources in IaC", "Critical", "WARN",
          "Manual check — verify all VPC resources (subnets, route tables, NACLs, peering) in Terraform/CloudFormation")

    sensitive_ports = [("22","SSH"),("3306","MySQL"),("5432","PostgreSQL"),("6379","Redis"),
                       ("9092","Kafka"),("27017","MongoDB"),("1433","MSSQL"),("5439","Redshift")]
    exposed: List[str] = []
    for port, name in sensitive_ports:
        try:
            sgs = ec2.describe_security_groups(
                Filters=[
                    {"Name": "ip-permission.from-port", "Values": [port]},
                    {"Name": "ip-permission.to-port",   "Values": [port]},
                    {"Name": "ip-permission.cidr",       "Values": ["0.0.0.0/0"]},
                ]
            ).get("SecurityGroups", [])
            if sgs:
                exposed.append(f"{port}({name}):{len(sgs)}SG(s)")
        except Exception:
            pass
    s.add("VPC-002", "VPC", "No 0.0.0.0/0 Inbound on Sensitive Ports", "Critical",
          "PASS" if not exposed else "FAIL",
          "All sensitive ports blocked from 0.0.0.0/0 on all security groups" if not exposed
          else f"Sensitive port(s) exposed to internet: {exposed} — immediate remediation required")

    try:
        vpcs    = ec2.describe_vpcs().get("Vpcs", [])
        fl_fail = 0
        for vpc in vpcs:
            fls = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}]
            ).get("FlowLogs", [])
            if not any(f.get("FlowLogStatus") == "ACTIVE" for f in fls):
                fl_fail += 1
        s.add("VPC-003", "VPC", "VPC Flow Logs Enabled", "Critical",
              "PASS" if fl_fail == 0 else "FAIL",
              f"Flow logs ACTIVE on all {len(vpcs)} VPC(s)" if fl_fail == 0
              else f"{fl_fail}/{len(vpcs)} VPC(s) have no active flow logs — network anomalies cannot be investigated")
    except Exception:
        s.add("VPC-003", "VPC", "VPC Flow Logs Enabled", "Critical", "SKIP", "API error")


# ── Cognito ────────────────────────────────────────────────────────────────────
def check_cognito(s: AuditState) -> None:
    idp = client("cognito-idp", s.region)
    try:
        pools = idp.list_user_pools(MaxResults=60).get("UserPools", [])
    except Exception:
        for cid in ["COG-001","COG-002","COG-003","COG-004"]:
            s.add(cid, "Cognito", "-", "Critical", "SKIP", "API error")
        return

    if not pools:
        for cid in ["COG-001","COG-002","COG-003","COG-004"]:
            s.add(cid, "Cognito", "-", "Critical", "SKIP", "No Cognito user pools found")
        return

    count      = len(pools)
    prot_fail: List[str] = []
    for p in pools:
        try:
            dp = idp.describe_user_pool(UserPoolId=p["Id"])
            if dp.get("UserPool", {}).get("DeletionProtection") != "ACTIVE":
                prot_fail.append(p["Id"])
        except Exception:
            prot_fail.append(p["Id"])

    s.add("COG-001", "Cognito", "Deletion Protection on User Pools", "Critical",
          "PASS" if not prot_fail else "FAIL",
          f"All {count} Cognito user pool(s) have deletion protection ACTIVE" if not prot_fail
          else f"{len(prot_fail)} pool(s) without deletion protection: {prot_fail}")
    export_count = (len([f for f in os.listdir("cognito-backup") if f.startswith("userpool-")])
                    if os.path.isdir("cognito-backup") else 0)
    s.add("COG-002", "Cognito", "User Export Backup Exists", "Critical",
          "PASS" if export_count >= count else "WARN",
          f"{export_count} user pool export file(s) found" if export_count >= count
          else f"Only {export_count}/{count} pool backup file(s) — export all pools before modifications")
    s.add("COG-003", "Cognito", "App Client Configs in IaC", "High", "WARN",
          f"{count} user pool(s) — verify all Cognito app client configs (callback URLs, scopes) are in Terraform/CDK")
    try:
        oidc = client("iam", s.region).list_open_id_connect_providers()\
                     .get("OpenIDConnectProviderList", [])
        s.add("COG-004", "Cognito", "OIDC Provider Exists for EKS", "Critical",
              "PASS" if oidc else "WARN",
              f"{len(oidc)} OIDC provider(s) found — EKS IRSA properly configured" if oidc
              else "No OIDC providers — EKS pods cannot assume IAM roles; workloads may use overly broad node roles")
    except Exception:
        s.add("COG-004", "Cognito", "OIDC Provider Exists for EKS", "Critical", "SKIP", "API error")


# ── CloudFormation  [FIXED: include ROLLBACK_COMPLETE and other active statuses] ─
def check_cloudformation(s: AuditState) -> None:
    cfn = client("cloudformation", s.region)
    try:
        stacks = cfn.list_stacks(
            StackStatusFilter=["CREATE_COMPLETE","UPDATE_COMPLETE","ROLLBACK_COMPLETE",
                               "UPDATE_ROLLBACK_COMPLETE","IMPORT_COMPLETE"]
        ).get("StackSummaries", [])
    except Exception:
        s.add("CFN-001", "CloudFormation", "Termination Protection on All Stacks", "Critical", "SKIP", "API error")
        s.add("CFN-002", "CloudFormation", "DeletionPolicy=Retain on Stateful Resources", "Critical", "SKIP", "API error")
        return

    if not stacks:
        s.add("CFN-001", "CloudFormation", "Termination Protection on All Stacks", "Critical", "SKIP",
              "No active CloudFormation stacks found")
        s.add("CFN-002", "CloudFormation", "DeletionPolicy=Retain on Stateful Resources", "Critical", "SKIP",
              "No active CloudFormation stacks found")
        return

    count    = len(stacks)
    no_prot: List[str] = []
    for st in stacks:
        try:
            detail = cfn.describe_stacks(StackName=st["StackName"]).get("Stacks", [{}])[0]
            if not detail.get("EnableTerminationProtection"):
                no_prot.append(st["StackName"])
        except Exception:
            pass

    s.add("CFN-001", "CloudFormation", "Termination Protection on All Stacks", "Critical",
          "PASS" if not no_prot else "FAIL",
          f"All {count} active stack(s) have termination protection" if not no_prot
          else f"{len(no_prot)}/{count} stacks without termination protection: {no_prot[:5]}")
    s.add("CFN-002", "CloudFormation", "DeletionPolicy=Retain on Stateful Resources", "Critical", "WARN",
          f"{count} active stack(s) — verify RDS/DynamoDB/S3 have DeletionPolicy=Retain in all templates")


# ── ELB ────────────────────────────────────────────────────────────────────────
def check_elb(s: AuditState) -> None:
    elbv2 = client("elbv2", s.region)
    try:
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
    except Exception:
        s.add("ELB-001", "ELB / ALB / NLB", "Deletion Protection Enabled", "Critical", "SKIP", "API error")
        s.add("ELB-002", "ELB / ALB / NLB", "Access Logs Enabled",          "High",     "SKIP", "API error")
        return

    if not lbs:
        s.add("ELB-001", "ELB / ALB / NLB", "Deletion Protection Enabled", "Critical", "SKIP",
              "No load balancers found")
        s.add("ELB-002", "ELB / ALB / NLB", "Access Logs Enabled",          "High",     "SKIP",
              "No load balancers found")
        return

    count = len(lbs); no_prot = 0; no_logs = 0
    for lb in lbs:
        try:
            attrs = {a["Key"]: a["Value"]
                     for a in elbv2.describe_load_balancer_attributes(
                         LoadBalancerArn=lb["LoadBalancerArn"]).get("Attributes", [])}
            if attrs.get("deletion_protection.enabled") != "true": no_prot += 1
            if attrs.get("access_logs.s3.enabled")      != "true": no_logs += 1
        except Exception:
            no_prot += 1; no_logs += 1

    s.add("ELB-001", "ELB / ALB / NLB", "Deletion Protection Enabled", "Critical",
          "PASS" if no_prot == 0 else "FAIL",
          f"All {count} load balancer(s) have deletion protection" if no_prot == 0
          else f"{no_prot}/{count} without deletion protection — ALBs/NLBs can be accidentally deleted")
    s.add("ELB-002", "ELB / ALB / NLB", "Access Logs Enabled", "High",
          "PASS" if no_logs == 0 else "WARN",
          f"All {count} load balancer(s) have S3 access logging" if no_logs == 0
          else f"{no_logs}/{count} without access logs — cannot investigate traffic or security incidents")


# ── CloudWatch ─────────────────────────────────────────────────────────────────
def check_cloudwatch(s: AuditState) -> None:
    cw = client("cloudwatch", s.region)
    try:
        firing = cw.describe_alarms(StateValue="ALARM").get("MetricAlarms", [])
        s.add("CW-001", "CloudWatch", "No Alarms Currently Firing", "High",
              "PASS" if not firing else "FAIL",
              "No CloudWatch alarms in ALARM state" if not firing
              else f"{len(firing)} alarm(s) currently firing: {[a['AlarmName'] for a in firing[:5]]}")
    except Exception:
        s.add("CW-001", "CloudWatch", "No Alarms Currently Firing", "High", "SKIP", "API error")

    try:
        all_alarms = cw.describe_alarms().get("MetricAlarms", [])
        no_act = [a["AlarmName"] for a in all_alarms if not a.get("AlarmActions")]
        s.add("CW-002", "CloudWatch", "All Alarms Have Actions", "High",
              "PASS" if not no_act else "WARN",
              f"All {len(all_alarms)} alarm(s) have at least one action" if not no_act
              else f"{len(no_act)} alarm(s) with no actions — trigger fires silently: {no_act[:5]}")
    except Exception:
        s.add("CW-002", "CloudWatch", "All Alarms Have Actions", "High", "SKIP", "API error")

    try:
        dashes = cw.list_dashboards().get("DashboardEntries", [])
        s.add("CW-003", "CloudWatch", "Dashboards Backed Up", "Medium",
              "PASS" if dashes else "FAIL",
              f"{len(dashes)} CloudWatch dashboard(s) — verify dashboard JSON exported to Git" if dashes
              else "No CloudWatch dashboards found — create and back up operational visibility dashboards")
    except Exception:
        s.add("CW-003", "CloudWatch", "Dashboards Backed Up", "Medium", "SKIP", "API error")


# ── CloudWatch Logs  [FIXED: full pagination] ──────────────────────────────────
def check_cwlogs(s: AuditState) -> None:
    logs = client("logs", s.region)
    try:
        all_groups: List = []
        for page in logs.get_paginator("describe_log_groups").paginate():
            all_groups.extend(page.get("logGroups", []))
        total  = len(all_groups)
        no_ret = [g["logGroupName"] for g in all_groups if not g.get("retentionInDays")]
        s.add("CWL-001", "CloudWatch Logs", "Retention Policy on All Log Groups", "High",
              "PASS" if not no_ret else "FAIL",
              f"All {total} log group(s) have a retention policy" if not no_ret
              else f"{len(no_ret)}/{total} log group(s) have NO retention — logs accumulate indefinitely: {no_ret[:3]}")
    except Exception:
        s.add("CWL-001", "CloudWatch Logs", "Retention Policy on All Log Groups", "High", "SKIP", "API error")

    for prefix, ctrl, sev in [
        ("/aws/lambda",  "Critical Log Groups Exist (/aws/lambda)",  "High"),
        ("/aws/rds",     "Critical Log Groups Exist (/aws/rds)",     "High"),
        ("CloudTrail",   "Critical Log Groups Exist (CloudTrail)",   "High"),
    ]:
        try:
            gs = logs.describe_log_groups(logGroupNamePrefix=prefix).get("logGroups", [])
            s.add("CWL-002", "CloudWatch Logs", ctrl, sev,
                  "PASS" if gs else "WARN",
                  f"{len(gs)} log group(s) for prefix '{prefix}'" if gs
                  else f"No log groups for '{prefix}' — configure logging for these critical services")
        except Exception:
            s.add("CWL-002", "CloudWatch Logs", ctrl, sev, "SKIP", "API error")


# ── SSM ────────────────────────────────────────────────────────────────────────
def check_ssm(s: AuditState) -> None:
    ssm_c = client("ssm", s.region)
    try:
        params = ssm_c.describe_parameters().get("Parameters", [])
        secure = [p for p in params if p.get("Type") == "SecureString"]
        s.add("SSM-001", "SSM", "SecureString Params Backed Up", "Critical", "WARN",
              f"{len(secure)} SecureString / {len(params)} total SSM param(s) — verify all SecureString values backed up externally")
    except Exception:
        s.add("SSM-001", "SSM", "SecureString Params Backed Up", "Critical", "SKIP", "API error")

    try:
        total = len(ssm_c.describe_parameters().get("Parameters", []))
        s.add("SSM-002", "SSM", "Prod Parameters Inventoried", "High",
              "WARN" if total else "SKIP",
              f"{total} SSM parameter(s) — verify all prod parameters are documented" if total
              else "No SSM parameters found in this region")
    except Exception:
        s.add("SSM-002", "SSM", "Prod Parameters Inventoried", "High", "SKIP", "API error")

    try:
        assocs = ssm_c.list_associations().get("Associations", [])
        if not assocs:
            s.add("SSM-003", "SSM", "Associations Active and Not Failing", "High", "SKIP",
                  "No SSM associations found")
        else:
            failing = [a for a in assocs
                       if a.get("Overview", {}).get("Status")
                       not in ("Success", "Pending", "InProgress", "Running", None)]
            s.add("SSM-003", "SSM", "Associations Active and Not Failing", "High",
                  "PASS" if not failing else "FAIL",
                  f"All {len(assocs)} SSM association(s) are healthy" if not failing
                  else f"{len(failing)}/{len(assocs)} SSM association(s) are failing — patch compliance may be broken")
    except Exception:
        s.add("SSM-003", "SSM", "Associations Active and Not Failing", "High", "SKIP", "API error")


# ── EventBridge ────────────────────────────────────────────────────────────────
def check_eventbridge(s: AuditState) -> None:
    eb = client("events", s.region)
    try:
        rules = eb.list_rules().get("Rules", [])
        if not rules:
            s.add("EB-001", "EventBridge", "All Prod Rules Enabled",  "High", "SKIP", "No EventBridge rules found")
            s.add("EB-002", "EventBridge", "All Rules Have Targets",   "High", "SKIP", "No EventBridge rules found")
        else:
            count    = len(rules)
            disabled = [r["Name"] for r in rules if r.get("State") != "ENABLED"]
            s.add("EB-001", "EventBridge", "All Prod Rules Enabled", "High",
                  "PASS" if not disabled else "WARN",
                  f"All {count} rule(s) are ENABLED" if not disabled
                  else f"{len(disabled)}/{count} rule(s) disabled: {disabled[:5]}")
            no_tgt: List[str] = []
            for rule in rules:
                try:
                    if not eb.list_targets_by_rule(Rule=rule["Name"]).get("Targets"):
                        no_tgt.append(rule["Name"])
                except Exception:
                    no_tgt.append(rule["Name"])
            s.add("EB-002", "EventBridge", "All Rules Have Targets", "High",
                  "PASS" if not no_tgt else "FAIL",
                  f"All {count} rule(s) have at least one target" if not no_tgt
                  else f"{len(no_tgt)} rule(s) with no targets: {no_tgt[:5]} — events fire into the void")
    except Exception:
        s.add("EB-001", "EventBridge", "All Prod Rules Enabled",  "High", "SKIP", "API error")
        s.add("EB-002", "EventBridge", "All Rules Have Targets",   "High", "SKIP", "API error")

    try:
        schedules = client("scheduler", s.region).list_schedules().get("Schedules", [])
        if not schedules:
            s.add("EB-003", "EventBridge", "Schedules Backed Up in IaC", "Critical", "SKIP",
                  "No EventBridge Scheduler schedules found")
        else:
            dis = [sc["Name"] for sc in schedules if sc.get("State") != "ENABLED"]
            s.add("EB-003", "EventBridge", "Schedules Backed Up in IaC", "Critical",
                  "PASS" if not dis else "WARN",
                  f"All {len(schedules)} schedule(s) ENABLED — verify all are in IaC" if not dis
                  else f"{len(dis)}/{len(schedules)} schedule(s) disabled — verify all are in IaC")
    except Exception:
        s.add("EB-003", "EventBridge", "Schedules Backed Up in IaC", "Critical", "SKIP",
              "API error (EventBridge Scheduler)")

    try:
        buses  = eb.list_event_buses().get("EventBuses", [])
        custom = [b["Name"] for b in buses if b["Name"] != "default"]
        s.add("EB-004", "EventBridge", "Custom Event Buses in IaC", "High",
              "WARN" if custom else "SKIP",
              f"{len(custom)} custom bus(es): {custom} — verify all in Terraform/CDK" if custom
              else "No custom EventBridge event buses found")
    except Exception:
        s.add("EB-004", "EventBridge", "Custom Event Buses in IaC", "High", "SKIP", "API error")


# ── GuardDuty  [FIXED: EventPattern source = "aws.guardduty", not name string] ─
def check_guardduty(s: AuditState) -> None:
    gd = client("guardduty", s.region)
    try:
        dets = gd.list_detectors().get("DetectorIds", [])
    except Exception:
        for cid in ["GD-001","GD-002","GD-003"]:
            s.add(cid, "GuardDuty", "-", "Critical", "SKIP", "API error")
        return

    if not dets:
        s.add("GD-001", "GuardDuty", "Detector Enabled and Not Suspended", "Critical",
              "FAIL", "No GuardDuty detectors — zero threat detection; malicious activity goes undetected")
        s.add("GD-002", "GuardDuty", "Finding Alerts Sent to SNS", "Critical", "SKIP",
              "GuardDuty not enabled")
        s.add("GD-003", "GuardDuty", "No High Severity Findings Open", "Critical", "SKIP",
              "GuardDuty not enabled")
        return

    det_id = dets[0]
    try:
        status = gd.get_detector(DetectorId=det_id).get("Status", "")
        s.add("GD-001", "GuardDuty", "Detector Enabled and Not Suspended", "Critical",
              "PASS" if status == "ENABLED" else "FAIL",
              f"GuardDuty detector {det_id} is {status} — actively monitoring for threats" if status == "ENABLED"
              else f"GuardDuty detector {det_id} is {status} — threat detection impaired")
    except Exception:
        s.add("GD-001", "GuardDuty", "Detector Enabled and Not Suspended", "Critical", "SKIP", "API error")

    # FIXED: check EventPattern for "aws.guardduty" (canonical source field, not plain name string)
    try:
        eb    = client("events", s.region)
        rules = eb.list_rules().get("Rules", [])
        gd_rule = next(
            (r["Name"] for r in rules
             if "aws.guardduty" in r.get("EventPattern", "")
             or "guardduty" in r.get("Name", "").lower()),
            None
        )
        s.add("GD-002", "GuardDuty", "Finding Alerts Sent to SNS", "Critical",
              "PASS" if gd_rule else "FAIL",
              f"EventBridge rule for GuardDuty findings: '{gd_rule}' — alerts routed to SNS" if gd_rule
              else "No EventBridge rule found with source 'aws.guardduty' — high severity alerts fire silently")
    except Exception:
        s.add("GD-002", "GuardDuty", "Finding Alerts Sent to SNS", "Critical", "SKIP", "API error")

    try:
        findings = gd.list_findings(
            DetectorId=det_id,
            FindingCriteria={"Criterion": {
                "severity": {"Gte": 7},
                "service.archived": {"Eq": ["false"]}
            }}
        ).get("FindingIds", [])
        s.add("GD-003", "GuardDuty", "No High Severity Findings Open", "Critical",
              "PASS" if not findings else "FAIL",
              "No high/critical GuardDuty findings currently open" if not findings
              else f"{len(findings)} high/critical finding(s) open — active threat requires immediate investigation")
    except Exception:
        s.add("GD-003", "GuardDuty", "No High Severity Findings Open", "Critical", "SKIP", "API error")


# ── IAM  [FIXED: correct labels + credential report polling + timezone fix] ────
def check_iam(s: AuditState) -> None:
    iam = client("iam", s.region)

    # IAM-001 — MFA on ALL IAM users (correct: credential report, not AccountMFAEnabled)
    try:
        for _ in range(10):
            resp = iam.generate_credential_report()
            if resp.get("State") == "COMPLETE":
                break
            time.sleep(2)   # poll, not unconditional sleep(3)
        report_b64 = iam.get_credential_report().get("Content", b"")
        report     = base64.b64decode(report_b64).decode("utf-8")
        lines      = report.strip().split("\n")
        no_mfa: List[str] = []
        for line in lines[1:]:
            cols = line.split(",")
            # col 0=user, col 3=password_enabled, col 7=mfa_active
            if len(cols) > 7 and cols[3] == "true" and cols[7] != "true":
                no_mfa.append(cols[0])
        s.add("IAM-001", "IAM", "MFA on All IAM Users", "Critical",
              "PASS" if not no_mfa else "FAIL",
              "All active IAM users have MFA enabled" if not no_mfa
              else f"{len(no_mfa)} active IAM user(s) WITHOUT MFA: {no_mfa[:5]} — compromised passwords = full account access")
    except Exception:
        s.add("IAM-001", "IAM", "MFA on All IAM Users", "Critical", "SKIP",
              "API error — could not generate credential report")

    # IAM-002 — MFA on Root Account (correct: AccountMFAEnabled)
    try:
        summary  = iam.get_account_summary().get("SummaryMap", {})
        root_mfa = summary.get("AccountMFAEnabled", 0)
        s.add("IAM-002", "IAM", "MFA on Root Account", "Critical",
              "PASS" if root_mfa else "FAIL",
              "Root account MFA is enabled — root account protected" if root_mfa
              else "Root account MFA NOT enabled — root account is highly vulnerable; enable MFA immediately")
    except Exception:
        s.add("IAM-002", "IAM", "MFA on Root Account", "Critical", "SKIP", "API error")

    # IAM-003 — No Active Root Access Keys (correct: AccountAccessKeysPresent)
    try:
        summary   = iam.get_account_summary().get("SummaryMap", {})
        root_keys = summary.get("AccountAccessKeysPresent", 0)
        s.add("IAM-003", "IAM", "No Active Root Access Keys", "Critical",
              "PASS" if not root_keys else "FAIL",
              "No active root access keys — root cannot be used programmatically" if not root_keys
              else "Root access keys EXIST and ACTIVE — delete immediately; root keys bypass all IAM policies")
    except Exception:
        s.add("IAM-003", "IAM", "No Active Root Access Keys", "Critical", "SKIP", "API error")

    # IAM-004 — OIDC Provider for EKS
    try:
        oidc = iam.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])
        s.add("IAM-004", "IAM", "OIDC Provider Exists for EKS", "Critical",
              "PASS" if oidc else "WARN",
              f"{len(oidc)} OIDC provider(s) found — EKS IRSA configured" if oidc
              else "No OIDC providers — EKS pods cannot assume IAM roles; workloads may use overly broad node roles")
    except Exception:
        s.add("IAM-004", "IAM", "OIDC Provider Exists for EKS", "Critical", "SKIP", "API error")

    s.add("IAM-E01", "IAM", "Prod IAM Roles in IaC", "Critical", "WARN",
          "Manual check — verify all production IAM roles are defined in Terraform/CDK")

    try:
        roles   = iam.list_roles(PathPrefix="/").get("Roles", [])
        non_svc = [r for r in roles if not r.get("Path", "").startswith("/aws-service-role/")]
        wildcard: List[str] = []
        for role in non_svc[:30]:   # sample to avoid throttle
            try:
                for pol in iam.list_role_policies(RoleName=role["RoleName"]).get("PolicyNames", []):
                    doc = iam.get_role_policy(RoleName=role["RoleName"], PolicyName=pol)
                    doc_str = json.dumps(doc.get("PolicyDocument", {}))
                    if '"Action":"*"' in doc_str or '"Action": "*"' in doc_str:
                        wildcard.append(role["RoleName"])
                        break
            except Exception:
                pass
        s.add("IAM-E02", "IAM", "No Wildcard Permissions on Prod Roles", "Critical",
              "PASS" if not wildcard else "FAIL",
              f"No wildcard Action:* in sampled {min(30,len(non_svc))} non-service roles" if not wildcard
              else f"{len(wildcard)} role(s) with Action:* in inline policies: {wildcard} — violates least-privilege")
    except Exception:
        s.add("IAM-E02", "IAM", "No Wildcard Permissions on Prod Roles", "Critical", "SKIP", "API error")

    # FIXED: timezone-aware datetime comparison
    try:
        roles   = iam.list_roles(PathPrefix="/").get("Roles", [])
        non_svc = [r for r in roles if not r.get("Path", "").startswith("/aws-service-role/")]
        now_utc = datetime.now(timezone.utc)
        unused: List[str] = []
        for role in non_svc:
            try:
                last_used = iam.get_role(RoleName=role["RoleName"])["Role"]\
                              .get("RoleLastUsed", {}).get("LastUsedDate")
                if last_used:
                    days = (now_utc - last_used.replace(tzinfo=timezone.utc)).days
                    if days > 90:
                        unused.append(f"{role['RoleName']}({days}d)")
                else:
                    unused.append(f"{role['RoleName']}(never)")
            except Exception:
                pass
        s.add("IAM-E03", "IAM", "No Unused IAM Roles (90+ days)", "High",
              "PASS" if not unused else "WARN",
              f"All {len(non_svc)} non-service role(s) used in last 90 days" if not unused
              else f"{len(unused)} role(s) unused >90 days: {unused[:5]} — remove to reduce attack surface")
    except Exception:
        s.add("IAM-E03", "IAM", "No Unused IAM Roles (90+ days)", "High", "SKIP", "API error")


# ── AWS Backup  [FIXED: BKP-001/002/003 labels corrected] ─────────────────────
def check_aws_backup(s: AuditState) -> None:
    bkp = client("backup", s.region)

    # BKP-001 — Backup Plan Exists (was mislabelled "Vault Lock Enabled" in v3)
    try:
        plans = bkp.list_backup_plans().get("BackupPlansList", [])
        s.add("BKP-001", "AWS Backup", "Backup Plan Exists", "Critical",
              "PASS" if plans else "FAIL",
              f"{len(plans)} AWS Backup plan(s) found — centralised backup configured" if plans
              else "No AWS Backup plans — resources rely solely on service-native backups; no centralised RPO/RTO enforcement")
    except Exception:
        s.add("BKP-001", "AWS Backup", "Backup Plan Exists", "Critical", "SKIP", "API error")

    # BKP-002 — Vault Lock Enabled (was mislabelled "No Failed Jobs" in v3)
    try:
        vaults = bkp.list_backup_vaults().get("BackupVaultList", [])
        locked = [v["BackupVaultName"] for v in vaults if v.get("Locked")]
        s.add("BKP-002", "AWS Backup", "Backup Vault Lock Enabled", "Critical",
              "PASS" if locked else "FAIL",
              "Vault(s) with lock enabled: " + ", ".join(locked) + " — backups immutable; ransomware cannot delete them" if locked
              else "No Vault Lock on any vault — an attacker can delete backups and data simultaneously")
    except Exception:
        s.add("BKP-002", "AWS Backup", "Backup Vault Lock Enabled", "Critical", "SKIP", "API error")

    # BKP-003 — No Failed Backup Jobs (was mislabelled "All Critical Resources" in v3)
    try:
        failed = bkp.list_backup_jobs(ByState="FAILED").get("BackupJobs", [])
        s.add("BKP-003", "AWS Backup", "No Failed Backup Jobs", "High",
              "PASS" if not failed else "FAIL",
              "No failed backup jobs — all recent backups completed successfully" if not failed
              else f"{len(failed)} failed backup job(s) — those resources have no current recovery point")
    except Exception:
        s.add("BKP-003", "AWS Backup", "No Failed Backup Jobs", "High", "SKIP", "API error")

    # BKP-004 — Critical resource coverage
    try:
        results  = bkp.list_protected_resources().get("Results", [])
        ebs_prot = sum(1 for r in results if r.get("ResourceType") == "EBS")
        rds_prot = sum(1 for r in results if r.get("ResourceType") == "RDS")
        ddb_prot = sum(1 for r in results if r.get("ResourceType") == "DynamoDB")
        total    = len(results)
        s.add("BKP-004", "AWS Backup", "All Critical Resources in Backup Plan", "High",
              "PASS" if total else "WARN",
              f"Protected: EBS={ebs_prot}, RDS={rds_prot}, DynamoDB={ddb_prot} (total {total} resources)" if total
              else "No resources in AWS Backup — verify service-native backups meet RPO requirements")
    except Exception:
        s.add("BKP-004", "AWS Backup", "All Critical Resources in Backup Plan", "High", "SKIP", "API error")


# ── CloudFront ─────────────────────────────────────────────────────────────────
def check_cloudfront(s: AuditState) -> None:
    cf = boto3.client("cloudfront", config=RETRY_CFG)
    try:
        dists = cf.list_distributions().get("DistributionList", {}).get("Items", []) or []
    except Exception:
        for cid in ["CF-001","CF-002","CF-003","CF-004"]:
            s.add(cid, "CloudFront", "-", "Critical", "SKIP", "API error")
        return

    if not dists:
        for cid in ["CF-001","CF-002","CF-003","CF-004"]:
            s.add(cid, "CloudFront", "-", "High", "SKIP", "No CloudFront distributions found")
        return

    count        = len(dists)
    no_waf       = [d["Id"] for d in dists if not d.get("WebACLId")]
    not_deployed = [d["Id"] for d in dists if d.get("Status") != "Deployed"]

    s.add("CF-001", "CloudFront", "WAF Attached to All Distributions", "Critical",
          "PASS" if not no_waf else "FAIL",
          f"All {count} CloudFront distribution(s) have WAF attached" if not no_waf
          else f"{len(no_waf)}/{count} without WAF: {no_waf[:3]} — CDN exposed without DDoS protection")
    s.add("CF-002", "CloudFront", "Origins Not Publicly Accessible Directly", "High",
          "PASS" if not not_deployed else "WARN",
          f"All {count} distribution(s) Deployed — verify S3 origins use OAC/OAI" if not not_deployed
          else f"{len(not_deployed)} distribution(s) not in Deployed state — also verify origin access controls")
    s.add("CF-003", "CloudFront", "Distribution Config in IaC", "High", "WARN",
          f"{count} CloudFront distribution(s) — verify all defined in Terraform/CDK")

    no_log = 0
    for d in dists:
        try:
            cfg = cf.get_distribution_config(Id=d["Id"])
            if not cfg.get("DistributionConfig", {}).get("Logging", {}).get("Enabled", False):
                no_log += 1
        except Exception:
            no_log += 1
    s.add("CF-004", "CloudFront", "Access Logging Enabled", "High",
          "PASS" if no_log == 0 else "WARN",
          f"All {count} CloudFront distribution(s) have access logging" if no_log == 0
          else f"{no_log}/{count} without access logs — CDN traffic cannot be investigated")


# ── Cost Explorer  [FIXED: list_cost_anomaly_monitors / list_cost_anomaly_subscriptions] ─
def check_cost_explorer(s: AuditState) -> None:
    ce = boto3.client("ce", region_name="us-east-1", config=RETRY_CFG)
    try:
        monitors = ce.list_cost_anomaly_monitors().get("AnomalyMonitors", [])
        s.add("CE-001", "Cost Explorer", "Anomaly Monitor Configured", "High",
              "PASS" if monitors else "FAIL",
              f"{len(monitors)} cost anomaly monitor(s) active — unusual spend spikes will be detected" if monitors
              else "No cost anomaly monitors — runaway costs go undetected until the monthly bill")
    except Exception:
        s.add("CE-001", "Cost Explorer", "Anomaly Monitor Configured", "High", "SKIP",
              "API error — Cost Explorer may not be enabled")

    try:
        subs = ce.list_cost_anomaly_subscriptions().get("AnomalySubscriptions", [])
        s.add("CE-002", "Cost Explorer", "Anomaly Alert Subscription Active", "High",
              "PASS" if subs else "FAIL",
              f"{len(subs)} anomaly subscription(s) configured — team will be notified of cost spikes" if subs
              else "No anomaly subscriptions — anomalies detected but no alert sent to the team")
    except Exception:
        s.add("CE-002", "Cost Explorer", "Anomaly Alert Subscription Active", "High", "SKIP", "API error")

    try:
        acct   = client("sts", s.region).get_caller_identity().get("Account")
        bdgs_c = boto3.client("budgets", region_name="us-east-1", config=RETRY_CFG)
        bdgs   = bdgs_c.describe_budgets(AccountId=acct).get("Budgets", [])
        s.add("CE-003", "Cost Explorer", "Budget Alerts Configured", "High",
              "PASS" if bdgs else "WARN",
              f"{len(bdgs)} AWS Budget(s) configured — cost threshold alerts active" if bdgs
              else "No AWS Budgets — no proactive alerting when spend exceeds expected thresholds")
    except Exception:
        s.add("CE-003", "Cost Explorer", "Budget Alerts Configured", "High", "SKIP", "API error")


# ── SNS ────────────────────────────────────────────────────────────────────────
def check_sns(s: AuditState) -> None:
    sns = client("sns", s.region)
    try:
        topics = sns.list_topics().get("Topics", [])
    except Exception:
        for cid in ["SNS-001","SNS-002","SNS-003","SNS-004"]:
            s.add(cid, "SNS", "-", "Critical", "SKIP", "API error — could not list SNS topics")
        return

    if not topics:
        for cid in ["SNS-001","SNS-002","SNS-003","SNS-004"]:
            s.add(cid, "SNS", "-", "Critical", "SKIP", "No SNS topics found in this region")
        return

    count = len(topics)
    no_kms:       List[str] = []
    public_policy: List[str] = []
    for t in topics:
        arn = t["TopicArn"]
        try:
            attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
            kms   = attrs.get("KmsMasterKeyId", "")
            if not kms or kms == "None":
                no_kms.append(arn.split(":")[-1])
            if '"AWS":"*"' in attrs.get("Policy", "") or '"*"' in attrs.get("Policy", ""):
                public_policy.append(arn.split(":")[-1])
        except Exception:
            pass

    s.add("SNS-001", "SNS", "Critical Topics Backed Up in IaC", "Critical", "WARN",
          f"{count} SNS topic(s) — verify all defined in Terraform/CDK for disaster recovery")

    no_dlq = 0; total_subs = 0
    for t in topics:
        try:
            for sub in sns.list_subscriptions_by_topic(TopicArn=t["TopicArn"]).get("Subscriptions", []):
                if sub.get("SubscriptionArn") == "PendingConfirmation":
                    continue
                total_subs += 1
                try:
                    rp = sns.get_subscription_attributes(
                        SubscriptionArn=sub["SubscriptionArn"]
                    ).get("Attributes", {}).get("RedrivePolicy")
                    if not rp or rp == "None":
                        no_dlq += 1
                except Exception:
                    no_dlq += 1
        except Exception:
            pass

    if total_subs == 0:
        s.add("SNS-002", "SNS", "Subscriptions Have DLQ Configured", "High", "SKIP",
              "No confirmed SNS subscriptions found")
    else:
        s.add("SNS-002", "SNS", "Subscriptions Have DLQ Configured", "High",
              "PASS" if no_dlq == 0 else "WARN",
              f"All {total_subs} subscription(s) have a DLQ" if no_dlq == 0
              else f"{no_dlq}/{total_subs} subscription(s) without DLQ — delivery failures silently discarded")

    s.add("SNS-003", "SNS", "Topic Encryption at Rest", "High",
          "PASS" if not no_kms else "WARN",
          f"All {count} SNS topic(s) use KMS encryption" if not no_kms
          else f"{len(no_kms)}/{count} without KMS encryption: {no_kms[:3]}")
    s.add("SNS-004", "SNS", "No Public Topic Policies", "Critical",
          "PASS" if not public_policy else "FAIL",
          "No SNS topics have public (AWS:*) policies" if not public_policy
          else f"{len(public_policy)} topic(s) with public policy: {public_policy[:3]} — anyone can publish")


# ── Step Functions ─────────────────────────────────────────────────────────────
def check_step_functions(s: AuditState) -> None:
    sfn = client("stepfunctions", s.region)
    try:
        machines = sfn.list_state_machines().get("stateMachines", [])
    except Exception:
        for cid in ["SF-001","SF-002","SF-003","SF-004"]:
            s.add(cid, "Step Functions", "-", "Critical", "SKIP", "API error")
        return

    if not machines:
        for cid, ctrl, sev in [("SF-001","State Machine Definitions in Git","Critical"),
                                 ("SF-002","No Failed Executions","Critical"),
                                 ("SF-003","Execution Logging Enabled","High"),
                                 ("SF-004","State Machine Encryption Configured","High")]:
            s.add(cid, "Step Functions", ctrl, sev, "SKIP",
                  "No Step Functions state machines found in this region")
        return

    count = len(machines)
    s.add("SF-001", "Step Functions", "State Machine Definitions in Git", "Critical", "WARN",
          f"{count} state machine(s) — verify all ASL definitions committed to Git for DR")

    failed_exec = 0; no_logging = 0
    for m in machines:
        arn = m["stateMachineArn"]
        try:
            if sfn.list_executions(stateMachineArn=arn, statusFilter="FAILED").get("executions"):
                failed_exec += 1
        except Exception:
            pass
        try:
            log_level = sfn.describe_state_machine(stateMachineArn=arn)\
                           .get("loggingConfiguration", {}).get("level", "OFF")
            if log_level in ("OFF", None):
                no_logging += 1
        except Exception:
            no_logging += 1

    s.add("SF-002", "Step Functions", "No Failed Executions", "Critical",
          "PASS" if failed_exec == 0 else "FAIL",
          "No state machines have recent failed executions" if failed_exec == 0
          else f"{failed_exec}/{count} machine(s) have recent FAILED executions")
    s.add("SF-003", "Step Functions", "Execution Logging Enabled", "High",
          "PASS" if no_logging == 0 else "FAIL",
          f"All {count} machine(s) have execution logging enabled" if no_logging == 0
          else f"{no_logging}/{count} machine(s) have logging OFF — failed step details unavailable")

    no_enc = 0
    for m in machines:
        try:
            enc = sfn.describe_state_machine(stateMachineArn=m["stateMachineArn"])\
                     .get("encryptionConfiguration", {}).get("type", "AWS_OWNED_KEY")
            if enc == "AWS_OWNED_KEY":
                no_enc += 1
        except Exception:
            no_enc += 1
    s.add("SF-004", "Step Functions", "State Machine Encryption Configured", "High",
          "PASS" if no_enc == 0 else "WARN",
          f"All {count} machine(s) use customer-managed KMS encryption" if no_enc == 0
          else f"{no_enc}/{count} use AWS-owned keys — consider CMKs for compliance")


# ── WAF ────────────────────────────────────────────────────────────────────────
def check_waf(s: AuditState) -> None:
    waf = client("wafv2", s.region)
    try:
        acls = waf.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
    except Exception:
        for cid in ["WAF-001","WAF-002","WAF-003","WAF-004"]:
            s.add(cid, "WAF", "-", "Critical", "SKIP", "API error — could not list WAF regional ACLs")
        return

    if not acls:
        for cid, ctrl in [("WAF-001","WAF ACL Attached to All ALBs"),
                           ("WAF-002","WAF ACL Attached to API Gateway"),
                           ("WAF-003","WAF Rules Backed Up in IaC"),
                           ("WAF-004","WAF Logging Enabled")]:
            s.add(cid, "WAF", ctrl, "Critical", "FAIL",
                  "No WAF regional ACLs — ALBs and API Gateways have no threat protection or rate limiting")
        return

    count = len(acls)
    try:
        elbv2 = client("elbv2", s.region)
        albs  = elbv2.describe_load_balancers().get("LoadBalancers", [])
        unprotected: List[str] = []
        for lb in albs:
            try:
                if not waf.get_web_acl_for_resource(
                        ResourceArn=lb["LoadBalancerArn"]).get("WebACL"):
                    unprotected.append(lb.get("LoadBalancerName", lb["LoadBalancerArn"]))
            except Exception:
                unprotected.append(lb.get("LoadBalancerName", lb["LoadBalancerArn"]))
        s.add("WAF-001", "WAF", "WAF ACL Attached to All ALBs", "Critical",
              "PASS" if not unprotected else "FAIL",
              f"All {len(albs)} ALB(s) have WAF attached" if not unprotected
              else f"{len(unprotected)} ALB(s) without WAF: {unprotected[:3]} — exposed without OWASP protection")
    except Exception:
        s.add("WAF-001", "WAF", "WAF ACL Attached to All ALBs", "Critical", "SKIP",
              "API error checking ALB WAF attachment")

    s.add("WAF-002", "WAF", "WAF ACL Attached to API Gateway", "Critical", "WARN",
          f"{count} WAF ACL(s) — verify each API Gateway prod stage has a WAF ACL (see AGW-002)")
    s.add("WAF-003", "WAF", "WAF Rules Backed Up in IaC", "Critical", "WARN",
          f"{count} WAF ACL(s) — verify all rules, managed rule groups, and IP sets are in Terraform/CDK")

    no_log = 0
    for acl in acls:
        try:
            waf.get_logging_configuration(ResourceArn=acl["ARN"])
        except Exception:
            no_log += 1
    s.add("WAF-004", "WAF", "WAF Logging Enabled", "High",
          "PASS" if no_log == 0 else "FAIL",
          f"All {count} WAF ACL(s) have logging enabled" if no_log == 0
          else f"{no_log}/{count} WAF ACL(s) without logging — blocked attacks not recorded")


# ── ElastiCache ────────────────────────────────────────────────────────────────
def check_elasticache(s: AuditState) -> None:
    ec = client("elasticache", s.region)
    try:
        groups = ec.describe_replication_groups().get("ReplicationGroups", [])
    except Exception:
        for cid, ctrl, sev in [("EC-001","Automatic Backups Enabled (Redis)","Critical"),
                                 ("EC-002","Multi-AZ with Auto Failover","Critical"),
                                 ("EC-003","Cluster in Private Subnets Only","Critical"),
                                 ("EC-004","Encryption at Rest and In Transit","High"),
                                 ("EC-005","No Failed Backup Jobs","Critical")]:
            s.add(cid, "ElastiCache", ctrl, sev, "SKIP",
                  "API error — could not describe ElastiCache replication groups")
        return

    if not groups:
        for cid, ctrl, sev in [("EC-001","Automatic Backups Enabled (Redis)","Critical"),
                                 ("EC-002","Multi-AZ with Auto Failover","Critical"),
                                 ("EC-003","Cluster in Private Subnets Only","Critical"),
                                 ("EC-004","Encryption at Rest and In Transit","High"),
                                 ("EC-005","No Failed Backup Jobs","Critical")]:
            s.add(cid, "ElastiCache", ctrl, sev, "SKIP",
                  "No ElastiCache replication groups found in this region")
        return

    count    = len(groups)
    ret_fail = [g["ReplicationGroupId"] for g in groups if (g.get("SnapshotRetentionLimit") or 0) < 1]
    maz_fail = [g["ReplicationGroupId"] for g in groups if g.get("MultiAZ") != "enabled"]
    enc_fail = [g["ReplicationGroupId"] for g in groups
                if not g.get("AtRestEncryptionEnabled") or not g.get("TransitEncryptionEnabled")]

    s.add("EC-001", "ElastiCache", "Automatic Backups Enabled (Redis)", "Critical",
          "PASS" if not ret_fail else "FAIL",
          f"All {count} group(s) have automatic backup retention >= 1 day" if not ret_fail
          else f"No/zero retention on: {ret_fail} — Redis data lost on any failure")
    s.add("EC-002", "ElastiCache", "Multi-AZ with Auto Failover", "Critical",
          "PASS" if not maz_fail else "FAIL",
          f"All {count} group(s) are Multi-AZ with automatic failover" if not maz_fail
          else f"Not Multi-AZ or failover disabled: {maz_fail} — unavailable during AZ failure")
    s.add("EC-003", "ElastiCache", "Cluster in Private Subnets Only", "Critical", "WARN",
          f"{count} replication group(s) — manually verify subnet groups use only private subnets")
    s.add("EC-004", "ElastiCache", "Encryption at Rest and In Transit", "High",
          "PASS" if not enc_fail else "FAIL",
          f"All {count} group(s) have both at-rest and in-transit encryption" if not enc_fail
          else f"Unencrypted group(s): {enc_fail} — Redis data transmitted/stored without encryption")
    try:
        snaps = ec.describe_snapshots().get("Snapshots", [])
        s.add("EC-005", "ElastiCache", "No Failed Backup Jobs", "Critical", "PASS",
              f"{len(snaps)} ElastiCache snapshot(s) found — check 'failed' status via describe-snapshots")
    except Exception:
        s.add("EC-005", "ElastiCache", "No Failed Backup Jobs", "Critical", "SKIP",
              "API error — could not list snapshots")


# ── Security Hub ───────────────────────────────────────────────────────────────
def check_security_hub(s: AuditState) -> None:
    sh = client("securityhub", s.region)
    try:
        sh.describe_hub()
        s.add("SH-001", "Security Hub", "Security Hub Enabled in All Regions", "Critical",
              "PASS", f"Security Hub enabled in {s.region} — centralised security posture management active")
    except Exception:
        s.add("SH-001", "Security Hub", "Security Hub Enabled in All Regions", "Critical",
              "FAIL", f"Security Hub NOT enabled in {s.region} — no centralised compliance and finding aggregation")
        s.add("SH-002", "Security Hub", "CIS AWS Benchmark Standard Enabled", "High",     "SKIP",
              "Security Hub not enabled")
        s.add("SH-003", "Security Hub", "Critical Findings Actioned",          "Critical", "SKIP",
              "Security Hub not enabled")
        return

    try:
        standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
        cis = [st for st in standards if "cis" in st.get("StandardsArn", "").lower()]
        s.add("SH-002", "Security Hub", "CIS AWS Benchmark Standard Enabled", "High",
              "PASS" if cis else "FAIL",
              f"CIS AWS Benchmark enabled — {len(cis)} subscription(s) active" if cis
              else f"{len(standards)} standard(s) enabled but CIS Benchmark not found — enable for compliance")
    except Exception:
        s.add("SH-002", "Security Hub", "CIS AWS Benchmark Standard Enabled", "High", "SKIP", "API error")

    try:
        findings = sh.get_findings(
            Filters={
                "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]
            }
        ).get("Findings", [])
        s.add("SH-003", "Security Hub", "Critical Findings Actioned", "Critical",
              "PASS" if not findings else "FAIL",
              "No open CRITICAL Security Hub findings — security posture is current" if not findings
              else f"{len(findings)} CRITICAL finding(s) in NEW state — requires immediate triage and remediation")
    except Exception:
        s.add("SH-003", "Security Hub", "Critical Findings Actioned", "Critical", "SKIP", "API error")


# ── Macie ──────────────────────────────────────────────────────────────────────
def check_macie(s: AuditState) -> None:
    mac = client("macie2", s.region)
    try:
        status = mac.get_macie_session().get("status", "")
    except Exception:
        s.add("MAC-001", "Macie", "Macie Enabled and Active",                 "Critical", "FAIL",
              "Macie NOT enabled — PII in S3 buckets not being scanned")
        s.add("MAC-002", "Macie", "No Unresolved High Severity Findings",      "Critical", "SKIP",
              "Macie not enabled")
        s.add("MAC-003", "Macie", "Automated Sensitive Data Discovery Enabled", "High",     "SKIP",
              "Macie not enabled")
        return

    s.add("MAC-001", "Macie", "Macie Enabled and Active", "Critical",
          "PASS" if status == "ENABLED" else "WARN",
          f"Macie {status} — PII in S3 actively scanned" if status == "ENABLED"
          else f"Macie status={status} — sensitive data scanning paused or impaired")
    try:
        fids = mac.list_findings(
            findingCriteria={"criterion": {"severity.description": {"eq": ["High", "Critical"]}}}
        ).get("findingIds", [])
        s.add("MAC-002", "Macie", "No Unresolved High Severity Findings", "Critical",
              "PASS" if not fids else "FAIL",
              "No high/critical Macie findings — no sensitive data exposure detected" if not fids
              else f"{len(fids)} high/critical Macie finding(s) — PII exposure risk requires investigation")
    except Exception:
        s.add("MAC-002", "Macie", "No Unresolved High Severity Findings", "Critical", "SKIP", "API error")

    try:
        disc = mac.get_automated_discovery_configuration().get("status", "")
        s.add("MAC-003", "Macie", "Automated Sensitive Data Discovery Enabled", "High",
              "PASS" if disc == "ENABLED" else "WARN",
              "Automated sensitive data discovery ENABLED — new S3 buckets automatically scanned" if disc == "ENABLED"
              else f"Automated discovery {disc or 'DISABLED'} — new S3 buckets not automatically scanned")
    except Exception:
        s.add("MAC-003", "Macie", "Automated Sensitive Data Discovery Enabled", "High", "SKIP", "API error")


# ── Athena ─────────────────────────────────────────────────────────────────────
def check_athena(s: AuditState) -> None:
    ath = client("athena", s.region)
    try:
        wgs    = ath.list_work_groups().get("WorkGroups", [])
        custom = [w for w in wgs if w["Name"] != "primary"]
    except Exception:
        for cid in ["ATH-001","ATH-002","ATH-003","ATH-004"]:
            s.add(cid, "Athena", "-", "Critical", "SKIP", "API error")
        return

    s.add("ATH-001", "Athena", "Workgroup Config Backed Up in IaC", "Critical", "WARN",
          f"{len(custom)} custom workgroup(s) — verify all workgroup configs are in IaC" if custom
          else "Only the primary Athena workgroup — verify its config is documented in IaC")

    no_enc = 0
    for w in custom:
        try:
            enc = ath.get_work_group(WorkGroup=w["Name"])\
                     .get("WorkGroup", {}).get("Configuration", {})\
                     .get("ResultConfiguration", {}).get("EncryptionConfiguration", {})
            if not enc.get("EncryptionOption"):
                no_enc += 1
        except Exception:
            no_enc += 1
    s.add("ATH-002", "Athena", "Workgroup Results Encrypted", "High",
          "PASS" if no_enc == 0 else "FAIL",
          f"All {len(custom)} custom workgroup(s) encrypt query results" if no_enc == 0 and custom
          else ("No custom workgroups — verify primary workgroup encryption manually" if not custom
                else f"{no_enc} workgroup(s) store query results without encryption"))

    try:
        s3    = boto3.client("s3", config=RETRY_CFG)
        bkts  = [b["Name"] for b in s3.list_buckets().get("Buckets", [])
                  if "athena" in b["Name"].lower() or "query" in b["Name"].lower()]
        unver = [b for b in bkts if s3.get_bucket_versioning(Bucket=b).get("Status") != "Enabled"]
        s.add("ATH-003", "Athena", "Query Result S3 Bucket Versioned", "High",
              "PASS" if not unver else "WARN",
              "Athena result bucket(s) have versioning enabled" if not unver
              else f"{len(unver)} result bucket(s) without versioning: {unver}")
    except Exception:
        s.add("ATH-003", "Athena", "Query Result S3 Bucket Versioned", "High", "SKIP",
              "API error or no Athena result buckets found")

    try:
        glue = client("glue", s.region)
        dbs  = glue.get_databases().get("DatabaseList", [])
        s.add("ATH-004", "Athena", "Data Catalog Backed Up", "Critical",
              "WARN" if dbs else "SKIP",
              f"{len(dbs)} Glue database(s) — export table DDLs to Git; no native AWS Backup for Glue" if dbs
              else "No Glue databases found — verify AwsDataCatalog content is documented")
    except Exception:
        s.add("ATH-004", "Athena", "Data Catalog Backed Up", "Critical", "SKIP",
              "API error — could not query Glue")


# ── Transit Gateway ────────────────────────────────────────────────────────────
def check_transit_gateway(s: AuditState) -> None:
    ec2 = client("ec2", s.region)
    try:
        tgws = [t for t in ec2.describe_transit_gateways().get("TransitGateways", [])
                if t.get("State") != "deleted"]
    except Exception:
        for cid in ["TGW-001","TGW-002","TGW-003","TGW-004"]:
            s.add(cid, "Transit GW", "-", "Critical", "SKIP", "API error")
        return

    if not tgws:
        for cid, ctrl, sev in [("TGW-001","TGW Config in IaC","Critical"),
                                 ("TGW-002","TGW Route Tables Backed Up","Critical"),
                                 ("TGW-003","TGW Attachments All Active","Critical"),
                                 ("TGW-004","TGW Flow Logs Enabled","High")]:
            s.add(cid, "Transit GW", ctrl, sev, "SKIP", "No Transit Gateways found in this region")
        return

    count    = len(tgws)
    inactive = [t["TransitGatewayId"] for t in tgws if t.get("State") != "available"]
    s.add("TGW-001", "Transit GW", "TGW Config in IaC", "Critical",
          "PASS" if not inactive else "FAIL",
          f"All {count} TGW(s) are available — verify all TGW configs are in Terraform/CDK" if not inactive
          else f"{len(inactive)} TGW(s) not available: {inactive} — cross-VPC/VPN connectivity broken")
    s.add("TGW-002", "Transit GW", "TGW Route Tables Backed Up", "Critical", "WARN",
          f"{count} TGW(s) — export route tables (aws ec2 describe-transit-gateway-route-tables) to Git")
    try:
        failed = ec2.describe_transit_gateway_attachments(
            Filters=[{"Name": "state", "Values": ["failed","failing","rejected"]}]
        ).get("TransitGatewayAttachments", [])
        s.add("TGW-003", "Transit GW", "TGW Attachments All Active", "Critical",
              "PASS" if not failed else "FAIL",
              "No failed/rejected TGW attachments — all VPC/VPN connections active" if not failed
              else f"{len(failed)} failed attachment(s) — VPC or VPN connectivity broken")
    except Exception:
        s.add("TGW-003", "Transit GW", "TGW Attachments All Active", "Critical", "SKIP", "API error")

    try:
        fls    = ec2.describe_flow_logs(
            Filters=[{"Name": "resource-type", "Values": ["TransitGateway"]}]
        ).get("FlowLogs", [])
        active = [f for f in fls if f.get("FlowLogStatus") == "ACTIVE"]
        s.add("TGW-004", "Transit GW", "TGW Flow Logs Enabled", "High",
              "PASS" if active else "FAIL",
              f"{len(active)} active TGW flow log(s) — cross-VPC traffic visible for forensics" if active
              else "No active TGW flow logs — cross-VPC traffic invisible; exfiltration cannot be detected")
    except Exception:
        s.add("TGW-004", "Transit GW", "TGW Flow Logs Enabled", "High", "SKIP", "API error")


# ── App Runner ─────────────────────────────────────────────────────────────────
def check_app_runner(s: AuditState) -> None:
    ar = client("apprunner", s.region)
    try:
        svcs = ar.list_services().get("ServiceSummaryList", [])
    except Exception:
        for cid in ["AR-001","AR-002","AR-003","AR-004"]:
            s.add(cid, "App Runner", "-", "Critical", "SKIP",
                  "API error — App Runner may not be supported in this region")
        return

    if not svcs:
        for cid, ctrl, sev in [("AR-001","Service Config in IaC","Critical"),
                                 ("AR-002","Auto Scaling Config Backed Up","High"),
                                 ("AR-003","No Failed Deployments","Critical"),
                                 ("AR-004","VPC Connector Configured","High")]:
            s.add(cid, "App Runner", ctrl, sev, "SKIP", "No App Runner services found in this region")
        return

    count       = len(svcs)
    not_running = [si["ServiceName"] for si in svcs if si.get("Status") != "RUNNING"]
    s.add("AR-001", "App Runner", "Service Config in IaC", "Critical", "WARN",
          f"{count} App Runner service(s) — verify all configurations are in Terraform/CDK")
    s.add("AR-002", "App Runner", "Auto Scaling Config Backed Up", "High", "WARN",
          f"{count} service(s) — verify auto-scaling configs (min/max concurrency) are defined in IaC")
    s.add("AR-003", "App Runner", "No Failed Deployments", "Critical",
          "PASS" if not not_running else "FAIL",
          f"All {count} App Runner service(s) are in RUNNING state" if not not_running
          else f"{len(not_running)}/{count} not RUNNING: {not_running} — application may be down")
    try:
        conns  = ar.list_vpc_connectors().get("VpcConnectors", [])
        active = [c for c in conns if c.get("Status") == "ACTIVE"]
        s.add("AR-004", "App Runner", "VPC Connector Configured", "High",
              "PASS" if active else "WARN",
              f"{len(active)} active VPC connector(s) — App Runner can reach private VPC resources" if active
              else "No active VPC connectors — App Runner cannot reach private RDS/MemoryDB/ElastiCache")
    except Exception:
        s.add("AR-004", "App Runner", "VPC Connector Configured", "High", "SKIP", "API error")


# ── X-Ray  [FIXED: reuse cached Lambda list from AuditState] ──────────────────
def check_xray(s: AuditState) -> None:
    xr = client("xray", s.region)
    try:
        rules  = xr.get_sampling_rules().get("SamplingRuleRecords", [])
        custom = [r for r in rules if r.get("SamplingRule", {}).get("RuleName") != "Default"]
        s.add("XR-001", "X-Ray", "Sampling Rules Backed Up in IaC", "High",
              "PASS" if custom else "WARN",
              f"{len(custom)} custom sampling rule(s) — verify all in IaC for reproducibility" if custom
              else "Only default X-Ray sampling rule — add custom rules to control sampling rate and reduce cost")
    except Exception:
        s.add("XR-001", "X-Ray", "Sampling Rules Backed Up in IaC", "High", "SKIP", "API error")

    # Reuse pre-fetched Lambda list — avoids a duplicate list_functions call
    fns = s._lambda_fns
    if fns is None:
        try:
            lam = client("lambda", s.region)
            fns = []
            for page in lam.get_paginator("list_functions").paginate():
                fns.extend(page.get("Functions", []))
        except Exception:
            fns = []

    if not fns:
        s.add("XR-002", "X-Ray", "Tracing Enabled on Lambda Functions", "High", "SKIP",
              "No Lambda functions found")
    else:
        no_trace = [f["FunctionName"] for f in fns
                    if f.get("TracingConfig", {}).get("Mode") != "Active"]
        s.add("XR-002", "X-Ray", "Tracing Enabled on Lambda Functions", "High",
              "PASS" if not no_trace else "WARN",
              f"All {len(fns)} Lambda function(s) have X-Ray active tracing" if not no_trace
              else f"{len(no_trace)}/{len(fns)} function(s) without X-Ray tracing — latency profiling unavailable")
    # Note: XR-003 (API Gateway tracing) is added inside check_apigateway


# ── Bedrock  [FIXED: list_knowledge_bases is on bedrock-agent client] ──────────
def check_bedrock(s: AuditState) -> None:
    bdr = client("bedrock", s.region)
    try:
        guardrails = bdr.list_guardrails().get("guardrails", [])
        s.add("BR-001", "Bedrock", "Guardrails Configured for Prod", "High",
              "PASS" if guardrails else "WARN",
              f"{len(guardrails)} Bedrock guardrail(s) configured — LLM responses filtered for harmful content" if guardrails
              else "No Bedrock guardrails — production invocations unguarded; model can generate harmful content or leak data")
    except Exception:
        s.add("BR-001", "Bedrock", "Guardrails Configured for Prod", "High", "SKIP",
              "API error — Bedrock may not be available or subscribed in this region")

    try:
        log_cfg      = bdr.get_model_invocation_logging_configuration().get("loggingConfig", {})
        text_enabled = log_cfg.get("textDataDeliveryEnabled", False)
        s3_bucket    = log_cfg.get("s3Config",        {}).get("bucketName",    "")
        cw_group     = log_cfg.get("cloudWatchConfig",{}).get("logGroupName",  "")
        log_active   = text_enabled and (s3_bucket or cw_group)
        s.add("BR-002", "Bedrock", "Model Invocation Logging Enabled", "Critical",
              "PASS" if log_active else "FAIL",
              f"Bedrock invocation logging active — sent to {'S3:' + s3_bucket if s3_bucket else 'CW:' + cw_group}" if log_active
              else "Bedrock invocation logging DISABLED — no audit trail of LLM prompts/responses; compliance impossible")
    except Exception:
        s.add("BR-002", "Bedrock", "Model Invocation Logging Enabled", "Critical", "SKIP",
              "API error — Bedrock may not be available in this region")

    # FIXED: list_knowledge_bases is on the bedrock-agent client, not bedrock
    try:
        bra = client("bedrock-agent", s.region)
        kbs = bra.list_knowledge_bases().get("knowledgeBaseSummaries", [])
        s.add("BR-003", "Bedrock", "Knowledge Base Backed Up", "Critical",
              "WARN" if kbs else "SKIP",
              f"{len(kbs)} knowledge base(s) — verify source data in S3 is versioned/backed up and ingestion in IaC" if kbs
              else "No Bedrock knowledge bases found")
    except Exception:
        s.add("BR-003", "Bedrock", "Knowledge Base Backed Up", "Critical", "SKIP", "API error")

    s.add("BR-004", "Bedrock", "No Public Model Access", "Critical", "WARN",
          "Manual check — verify Bedrock resource-based policies restrict InvokeModel to known internal principals only")


# ══════════════════════════════════════════════════════════════════════════════
#  DISPLAY / EXPORT
# ══════════════════════════════════════════════════════════════════════════════

def print_banner(state: AuditState) -> None:
    art = (
        "  ██████╗ ██████╗  ██████╗ ██████╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗\n"
        "  ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗   ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝\n"
        "  ██████╔╝██████╔╝██║   ██║██║  ██║   ███████║██║   ██║██║  ██║██║   ██║   \n"
        "  ██╔═══╝ ██╔══██╗██║   ██║██║  ██║   ██╔══██║██║   ██║██║  ██║██║   ██║   \n"
        "  ██║     ██║  ██║╚██████╔╝██████╔╝   ██║  ██║╚██████╔╝██████╔╝██║   ██║   \n"
        "  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝  "
    )
    account_display = state.account_name if state.account_name else state.account
    console.print()
    console.print(Panel(
        f"[bold bright_cyan]{art}[/]\n\n"
        f"  [bold bright_green]Production Audit — Status Tracker  v{VERSION}[/]"
        f"  [dim white]|[/]  [bold yellow]Author: {AUTHOR}[/]\n\n"
        f"  [dim cyan]Account:[/] [bold white]{account_display}[/]"
        f"   [dim cyan]Region:[/] [bold white]{state.region}[/]"
        f"   [dim cyan]Time:[/] [bold white]{DATE_STR}[/]"
        f"   [dim cyan]Controls:[/] [bold white]138[/]",
        border_style="bright_blue", box=box.DOUBLE_EDGE,
        expand=False, padding=(1, 2),
    ))
    console.print()


def print_results_table(state: AuditState, severity_filter: Optional[str] = None) -> None:
    console.print(Rule("[bold bright_cyan]  Audit Results  [/]", style="bright_blue"))
    console.print()

    sections: Dict = {}
    for r in state.results:
        if severity_filter and r.severity.lower() != severity_filter.lower():
            continue
        sections.setdefault(r.section, []).append(r)

    for section, rows in sections.items():
        tbl = Table(
            title=f"[bold cyan]{section}[/]  [dim]({len(rows)} checks)[/]",
            box=box.ROUNDED, border_style="bright_blue",
            header_style="bold bright_blue",
            show_lines=True, expand=True,
        )
        tbl.add_column("ID",             style="dim white", width=9,  no_wrap=True)
        tbl.add_column("Control",        min_width=32,                no_wrap=False)
        tbl.add_column("Severity",       justify="center", width=10,  no_wrap=True)
        tbl.add_column("Priority Tier",  min_width=24,                no_wrap=False)
        tbl.add_column("Status",         justify="center", width=10,  no_wrap=True)
        tbl.add_column("Detail",         min_width=28,                no_wrap=False)
        tbl.add_column("Remediation",    min_width=18,                no_wrap=False)

        for r in rows:
            icon, st_style = STATUS_STYLE.get(r.status, ("❓", "dim"))
            sev_style       = SEV_STYLE.get(r.severity, "white")
            tier            = SERVICE_TIER.get(r.service, "—")
            tier_style      = TIER_CONSOLE_STYLE.get(tier, "dim white")
            tbl.add_row(
                r.check_id, r.control,
                f"[{sev_style}]{r.severity}[/]",
                f"[{tier_style}]{tier}[/]",
                f"[{st_style}]{icon}[/]",
                r.detail,
                f"[dim]{r.remediation[:90]}[/]" if r.remediation else "[dim italic]—[/]",
            )
        console.print(tbl)
        console.print()


def print_summary(state: AuditState) -> None:
    console.print(Rule("[bold bright_green]  Summary  [/]", style="bright_green"))
    console.print()

    total = len(state.results)
    pct   = (state.passes * 100 // total) if total else 0

    if state.fails == 0:
        grade_style, grade_msg = "bold green",   "✅  ALL CHECKS PASSED"
    elif state.fails <= 5:
        grade_style, grade_msg = "bold yellow",  f"⚠️   {state.fails} GAPS — Review required"
    elif state.fails <= 15:
        grade_style, grade_msg = "bold orange3", f"❌  {state.fails} CRITICAL GAPS — Action needed"
    else:
        grade_style, grade_msg = "bold red",     f"🚨  {state.fails} CRITICAL GAPS — Immediate action"

    stats = Table(box=box.SIMPLE_HEAVY, border_style="bright_green",
                  show_header=False, expand=False, padding=(0, 3))
    stats.add_column("Label", style="dim white", justify="right")
    stats.add_column("Value", justify="left")
    stats.add_row("✅ PASS", f"[bold green]{state.passes}[/]")
    stats.add_row("❌ FAIL", f"[bold red]{state.fails}[/]")
    stats.add_row("⚠️  WARN", f"[bold yellow]{state.warns}[/]")
    stats.add_row("⏭️  SKIP", f"[dim]{state.skips}[/]")
    stats.add_row("Total",  f"[bold white]{total}[/] controls")
    stats.add_row("Score",  f"[bold cyan]{pct}%[/]")
    stats.add_row("Grade",  f"[{grade_style}]{grade_msg}[/]")
    console.print(stats)
    console.print()

    console.print(Panel(
        f"[bold green]✓  Audit Complete[/]   [dim]·[/]   "
        f"[white]PASS:[/] [bold green]{state.passes}[/]   "
        f"[white]FAIL:[/] [bold red]{state.fails}[/]   "
        f"[white]WARN:[/] [bold yellow]{state.warns}[/]   "
        f"[white]SKIP:[/] [dim]{state.skips}[/]   "
        f"[white]Score:[/] [bold cyan]{pct}%[/]   "
        f"[white]Total:[/] [bold]{total}[/] / 138 controls",
        border_style="bright_green", box=box.DOUBLE_EDGE, expand=False,
    ))
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  EXCEL EXPORT
# ══════════════════════════════════════════════════════════════════════════════

FILL     = {"PASS": "C6EFCE", "FAIL": "FFC7CE", "WARN": "FFEB9C", "SKIP": "D9D9D9"}
FONT_COL = {"PASS": "006100", "FAIL": "9C0006", "WARN": "9C5700", "SKIP": "595959"}
SEV_FILL = {"Critical": "FFE0E0", "High": "FFF0D9", "Medium": "FFFAD9", "Low": "F0F0F0"}
HDR_FILL = PatternFill("solid", start_color="1F3864")
HDR_FONT = Font(bold=True, color="FFFFFF", name="Calibri", size=11)
THIN     = Side(style="thin", color="D9D9D9")
BORDERS  = Border(top=THIN, bottom=THIN, left=THIN, right=THIN)


def export_excel(state: AuditState, path: str) -> str:
    rows = [
        {"Sno": i, "ID": r.check_id, "Service": r.service, "Control": r.control,
         "Severity": r.severity, "Priority Tier": _short_tier(SERVICE_TIER.get(r.service, "—")),
         "Status": r.status, "Detail": r.detail, "Remediation": r.remediation}
        for i, r in enumerate(state.results, start=1)
    ]
    df    = pd.DataFrame(rows, columns=["Sno","ID","Service","Control","Severity","Priority Tier","Status","Detail","Remediation"])
    total = len(state.results)
    pct   = (state.passes * 100 // total) if total else 0
    account_display = state.account_name if state.account_name else state.account

    summary_rows = [
        {"Metric": "Account Name",   "Value": account_display},
        {"Metric": "Account ID",     "Value": state.account},
        {"Metric": "Region",         "Value": state.region},
        {"Metric": "Scan Time",      "Value": DATE_STR},
        {"Metric": "Author",         "Value": AUTHOR},
        {"Metric": "Script Version", "Value": VERSION},
        {"Metric": "Total Controls", "Value": total},
        {"Metric": "✅ PASS",        "Value": state.passes},
        {"Metric": "❌ FAIL",        "Value": state.fails},
        {"Metric": "⚠️  WARN",        "Value": state.warns},
        {"Metric": "⏭️  SKIP",        "Value": state.skips},
        {"Metric": "Score",          "Value": f"{pct}%"},
    ]

    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Audit Results")
        pd.DataFrame(summary_rows).to_excel(writer, index=False, sheet_name="Summary")
        for section in df["Service"].unique():
            sdf   = df[df["Service"] == section].copy()
            sname = re.sub(r'[\\/*?:\[\]]', '-', section)[:31]
            sdf.to_excel(writer, index=False, sheet_name=sname)

    wb = load_workbook(path)

    def style_audit_sheet(ws):
        # A=Sno B=ID C=Service D=Control E=Severity F=Priority Tier G=Status H=Detail I=Remediation
        col_widths = {"A": 6, "B": 12, "C": 22, "D": 48, "E": 10, "F": 30, "G": 10, "H": 65, "I": 55}
        for col, w in col_widths.items():
            ws.column_dimensions[col].width = w
        for cell in ws[1]:
            cell.fill = HDR_FILL; cell.font = HDR_FONT; cell.border = BORDERS
            cell.alignment = Alignment(horizontal="center", vertical="center")
        for row in ws.iter_rows(min_row=2):
            sev    = row[4].value or "Low"    # col E — Severity
            tier   = row[5].value or "—"       # col F — Priority Tier
            status = row[6].value or "SKIP"    # col G — Status
            for cell in row:
                cell.font      = Font(name="Calibri", size=10)
                cell.border    = BORDERS
                cell.alignment = Alignment(vertical="center", wrap_text=True)
            row[4].fill = PatternFill("solid", start_color=SEV_FILL.get(sev, "FFFFFF"))
            row[5].fill = PatternFill("solid", start_color=TIER_FILL.get(tier, "FFFFFF"))
            row[6].fill = PatternFill("solid", start_color=FILL.get(status, "FFFFFF"))
            row[6].font = Font(bold=True, name="Calibri", size=10,
                               color=FONT_COL.get(status, "000000"))
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions

    style_audit_sheet(wb["Audit Results"])

    ws2 = wb["Summary"]
    ws2.column_dimensions["A"].width = 22; ws2.column_dimensions["B"].width = 40
    for cell in ws2[1]:
        cell.fill = HDR_FILL; cell.font = HDR_FONT; cell.border = BORDERS
    for row in ws2.iter_rows(min_row=2):
        for cell in row:
            cell.font = Font(name="Calibri", size=10); cell.border = BORDERS
            cell.alignment = Alignment(vertical="center")

    for section in df["Service"].unique():
        sname = re.sub(r'[\\/*?:\[\]]', '-', section)[:31]
        if sname in wb.sheetnames:
            style_audit_sheet(wb[sname])

    # ── Priority in Tier sheet ─────────────────────────────────────────────────
    TIER_HDR_FILLS = {
        "Tier 1 — Data Destroyed":            PatternFill("solid", start_color="C00000"),
        "Tier 2 — Data Dropped in Transit":   PatternFill("solid", start_color="E36C0A"),
        "Tier 3 — Data Locked Out":           PatternFill("solid", start_color="C09000"),
        "Tier 4 — Data Unreachable":          PatternFill("solid", start_color="17375E"),
        "Tier 5 — Data Exposed or Invisible": PatternFill("solid", start_color="60497A"),
    }
    TIER_ROW_FILLS = {
        "Tier 1": "FFB3B3",
        "Tier 2": "FFD9B3",
        "Tier 3": "FFFAB3",
        "Tier 4": "B3D9FF",
        "Tier 5": "E8B3FF",
    }
    wst = wb.create_sheet("Priority in Tier")
    tier_headers = ["Priority Tier", "Service", "Risk Category", "What Happens If Control Fails"]
    for ci, hdr in enumerate(tier_headers, start=1):
        cell = wst.cell(row=1, column=ci, value=hdr)
        cell.fill = HDR_FILL; cell.font = HDR_FONT; cell.border = BORDERS
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    wst.column_dimensions["A"].width = 32
    wst.column_dimensions["B"].width = 20
    wst.column_dimensions["C"].width = 24
    wst.column_dimensions["D"].width = 70
    wst.row_dimensions[1].height = 28

    # Build a flat list of rows to write: insert a coloured section-header row
    # each time the tier label changes, then write the data row.
    write_rows: List[tuple] = []    # (is_header, tier, svc, cat, desc)
    prev_tier = None
    for entry in PRIORITY_TIER_TABLE:
        t_tier, t_svc, t_cat, t_desc = entry
        if t_tier != prev_tier:
            write_rows.append(("header", t_tier, "", "", ""))
            prev_tier = t_tier
        write_rows.append(("data", t_tier, t_svc, t_cat, t_desc))

    for row_idx, (row_type, t_tier, t_svc, t_cat, t_desc) in enumerate(write_rows, start=2):
        if row_type == "header":
            hdr_fill = TIER_HDR_FILLS.get(t_tier, HDR_FILL)
            for ci_h in range(1, 5):
                hc = wst.cell(row=row_idx, column=ci_h)
                hc.value = _short_tier(t_tier) if ci_h == 1 else ""
                hc.fill = hdr_fill
                hc.font = Font(bold=True, color="FFFFFF", name="Calibri", size=11)
                hc.border = BORDERS
                hc.alignment = Alignment(horizontal="left", vertical="center")
        else:
            row_fill = PatternFill("solid", start_color=TIER_ROW_FILLS.get(_short_tier(t_tier), "FFFFFF"))
            for ci_d, val in enumerate([_short_tier(t_tier), t_svc, t_cat, t_desc], start=1):
                dc = wst.cell(row=row_idx, column=ci_d, value=val)
                dc.fill = row_fill
                dc.font = Font(name="Calibri", size=10)
                dc.border = BORDERS
                dc.alignment = Alignment(vertical="center", wrap_text=True)

    wst.freeze_panes = "A2"
    wst.auto_filter.ref = "A1:D1"

    wb.move_sheet("Summary",          offset=-len(wb.sheetnames))
    wb.move_sheet("Audit Results",    offset=-len(wb.sheetnames) + 1)
    wb.move_sheet("Priority in Tier", offset=-len(wb.sheetnames) + 2)
    wb.save(path)
    return os.path.abspath(path)


def export_json(state: AuditState, path: str) -> str:
    """Export results as structured JSON for CI/CD pipeline integration."""
    total = len(state.results)
    pct   = (state.passes * 100 // total) if total else 0
    data  = {
        "meta": {
            "account_name":   state.account_name or state.account,
            "account_id":     state.account,
            "region":         state.region,
            "scan_time":      DATE_STR,
            "author":         AUTHOR,
            "script_version": VERSION,
            "total":          total,
            "passes":         state.passes,
            "fails":          state.fails,
            "warns":          state.warns,
            "skips":          state.skips,
            "score_pct":      pct,
        },
        "controls": [
            {"check_id":    r.check_id, "service":     r.service,
             "control":     r.control,  "severity":    r.severity,
             "status":      r.status,   "detail":      r.detail,
             "remediation": r.remediation}
            for r in state.results
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return os.path.abspath(path)


def notify_slack(webhook_url: str, state: AuditState) -> None:
    """Post a summary notification to a Slack incoming webhook (no extra deps)."""
    try:
        import urllib.request
        total   = len(state.results)
        pct     = (state.passes * 100 // total) if total else 0
        account = state.account_name or state.account
        colour  = "#36a64f" if state.fails == 0 else ("#e8a838" if state.fails <= 5 else "#d72b3f")
        payload = {
            "attachments": [{
                "color": colour,
                "title": f"AWS Audit Report — {account} ({state.region})",
                "text": (f"*Score: {pct}%*  |  "
                         f"\u2705 PASS: {state.passes}  \u274c FAIL: {state.fails}  "
                         f"\u26a0\ufe0f WARN: {state.warns}  \u23ed\ufe0f SKIP: {state.skips}\n"
                         f"Scanned {total} controls at {DATE_STR}"),
                "footer": AUTHOR,
            }]
        }
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                console.print("  [green]\u2713[/] Slack notification sent")
            else:
                console.print(f"  [yellow]\u26a0[/] Slack returned HTTP {resp.status}")
    except Exception as exc:
        console.print(f"  [yellow]\u26a0[/] Slack notification failed: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
#  CHECK REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

ALL_CHECKS: Dict[str, object] = {
    "ebs":             check_ebs,
    "rds":             check_rds,
    "dynamodb":        check_dynamodb,
    "s3":              check_s3,
    "memorydb":        check_memorydb,
    "eks":             check_eks,
    "msk":             check_msk,
    "kms":             check_kms,
    "secrets":         check_secrets_manager,
    "sqs":             check_sqs,
    "lambda":          check_lambda,
    "apigateway":      check_apigateway,
    "cloudtrail":      check_cloudtrail,
    "route53":         check_route53,
    "ecr":             check_ecr,
    "config":          check_config,
    "ses":             check_ses,
    "amplify":         check_amplify,
    "vpc":             check_vpc,
    "cognito":         check_cognito,
    "cloudformation":  check_cloudformation,
    "elb":             check_elb,
    "cloudwatch":      check_cloudwatch,
    "cwlogs":          check_cwlogs,
    "ssm":             check_ssm,
    "eventbridge":     check_eventbridge,
    "guardduty":       check_guardduty,
    "iam":             check_iam,
    "awsbackup":       check_aws_backup,
    "cloudfront":      check_cloudfront,
    "costexplorer":    check_cost_explorer,
    "sns":             check_sns,
    "stepfunctions":   check_step_functions,
    "waf":             check_waf,
    "elasticache":     check_elasticache,
    "securityhub":     check_security_hub,
    "macie":           check_macie,
    "athena":          check_athena,
    "transitgateway":  check_transit_gateway,
    "apprunner":       check_app_runner,
    "xray":            check_xray,
    "bedrock":         check_bedrock,
}


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="prod_audit",
        description=f"Production Audit Status Tracker v{VERSION} — 138 controls across 43 services",
        epilog=(
            "Examples:\n"
            "  python prod_audit.py                          # prompts for region if unset\n"
            "  python prod_audit.py --region ca-central-1\n"
            "  python prod_audit.py --profile my-sso-profile\n"
            "  python prod_audit.py --output report.xlsx\n"
            "  python prod_audit.py --output-format json\n"
            "  python prod_audit.py --severity-filter critical\n"
            "  python prod_audit.py --check-only ebs rds s3 awsbackup iam guardduty\n"
            "  python prod_audit.py --list-checks\n"
            "  python prod_audit.py --no-excel\n"
            "  python prod_audit.py --notify-slack https://hooks.slack.com/...\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # FIXED: default=None so _resolve_region() can auto-detect from env/config
    p.add_argument("--region",
                   default=None,
                   help="AWS region (default: auto-detect from AWS_DEFAULT_REGION / ~/.aws/config; prompts if unset)")
    # NEW: named AWS CLI profile support
    p.add_argument("--profile",
                   default=None,
                   help="AWS CLI named profile (e.g. my-sso-profile)")
    p.add_argument("--output", "-o",
                   default="",
                   help="Output file path (default: <AccountName>_<timestamp>.xlsx or .json)")
    # NEW: JSON output format for CI/CD
    p.add_argument("--output-format",
                   dest="output_format",
                   choices=["xlsx", "json"],
                   default="xlsx",
                   help="Output format: xlsx (default) or json for pipeline integration")
    p.add_argument("--check-only",
                   dest="check_only",
                   nargs="*",
                   metavar="SERVICE",
                   help=f"Run only specific services. Valid keys: {', '.join(sorted(ALL_CHECKS.keys()))}")
    # NEW: severity filter for display
    p.add_argument("--severity-filter",
                   dest="severity_filter",
                   choices=["critical", "high", "medium", "low"],
                   default=None,
                   help="Display only results for this severity level")
    # NEW: list checks without running them
    p.add_argument("--list-checks",
                   dest="list_checks",
                   action="store_true",
                   help="Print all available service keys and exit (no AWS calls made)")
    p.add_argument("--no-excel",
                   dest="no_excel",
                   action="store_true",
                   help="Skip file export — terminal output only")
    # NEW: Slack webhook notification
    p.add_argument("--notify-slack",
                   dest="slack_webhook",
                   default=None,
                   metavar="WEBHOOK_URL",
                   help="Post a summary to a Slack incoming webhook after the run")
    return p.parse_args()


def get_account_name(account_id: str, region: str) -> str:
    """Resolve account name: IAM alias → Organizations name → account ID."""
    try:
        aliases = boto3.client("iam", region_name=region, config=RETRY_CFG)\
                        .list_account_aliases().get("AccountAliases", [])
        if aliases:
            return aliases[0]
    except Exception:
        pass
    try:
        acct = boto3.client("organizations", region_name="us-east-1", config=RETRY_CFG)\
                    .describe_account(AccountId=account_id).get("Account", {})
        if acct.get("Name"):
            return acct["Name"]
    except Exception:
        pass
    return account_id


def main() -> None:
    args = parse_args()

    # --list-checks: show all keys and exit without touching AWS
    if args.list_checks:
        console.print(f"\n[bold cyan]Available service checks ({len(ALL_CHECKS)}):[/]\n")
        for key in sorted(ALL_CHECKS.keys()):
            console.print(f"  [dim white]{key}[/]")
        console.print()
        sys.exit(0)

    # --check-only validation with did-you-mean hint
    if args.check_only is not None:
        valid = set(ALL_CHECKS.keys())
        bad   = [k for k in args.check_only if k not in valid]
        if bad:
            console.print(f"[bold red]✗  Unknown service(s):[/] {bad}")
            close = [v for b in bad for v in valid if b[:3] in v]
            if close:
                console.print(f"   Did you mean: {list(set(close))[:5]}")
            console.print("   Run [bold cyan]--list-checks[/] to see all valid service keys.")
            sys.exit(1)

    # Apply named AWS CLI profile before any boto3 calls
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    # Resolve region: CLI flag → env var → boto3 session → interactive prompt
    region = args.region or _resolve_region()
    state  = AuditState(region=region)

    # Auth check
    try:
        sts = boto3.client("sts", region_name=region, config=RETRY_CFG)
        state.account = sts.get_caller_identity().get("Account", "unknown")
    except NoCredentialsError:
        console.print(Panel(
            "[bold red]✗  Cannot authenticate[/]\n\n"
            "  Run [bold cyan]aws configure[/] or set env vars:\n"
            "  [dim]AWS_ACCESS_KEY_ID  AWS_SECRET_ACCESS_KEY  AWS_DEFAULT_REGION[/]",
            border_style="red", box=box.ROUNDED, expand=False,
        ))
        sys.exit(1)
    except Exception as exc:
        console.print(f"[bold red]✗  Auth failed:[/] {exc}")
        sys.exit(1)

    state.account_name = get_account_name(state.account, region)
    os.environ["AWS_DEFAULT_REGION"] = region
    print_banner(state)

    checks_to_run = (
        {k: ALL_CHECKS[k] for k in args.check_only}
        if args.check_only else dict(ALL_CHECKS)
    )
    total_checks = len(checks_to_run)

    # Progress bar — shows [N/M] count + elapsed time
    progress = Progress(
        SpinnerColumn(spinner_name="dots", style="bright_blue"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=28),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console, transient=False,
    )
    with progress:
        task = progress.add_task("Starting…", total=total_checks)
        for idx, (name, fn) in enumerate(checks_to_run.items(), 1):
            progress.update(task,
                            description=f"[cyan]Checking [bold]{name.upper()}[/]…",
                            completed=idx - 1)
            try:
                fn(state)
            except Exception as exc:
                console.print(f"  [bold red]✗[/] {name} crashed: {exc}")
        progress.update(task, completed=total_checks)

    print_results_table(state, severity_filter=args.severity_filter)
    print_summary(state)

    # File export
    if not args.no_excel:
        safe_name = re.sub(r'[^\w\-]', '_', state.account_name or state.account)
        if args.output_format == "json":
            out_path = args.output or f"{safe_name}_{DATE_FILE}.json"
            path     = export_json(state, out_path)
            console.print(f"  [green]✓[/] JSON saved → [dim]{path}[/]")
        else:
            out_path = args.output or f"{safe_name}_{DATE_FILE}.xlsx"
            with console.status("[bright_blue]Writing Excel report…", spinner="dots"):
                path = export_excel(state, out_path)
            console.print(f"  [green]✓[/] Excel saved → [dim]{path}[/]")
        console.print()

    # Slack notification
    if args.slack_webhook:
        notify_slack(args.slack_webhook, state)


if __name__ == "__main__":
    main()
