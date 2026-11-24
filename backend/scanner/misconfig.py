import concurrent.futures
import datetime
import re
from botocore.exceptions import ClientError

SENSITIVE_DB_PORTS = {
    1433: "MSSQL",
    3306: "MySQL/Aurora",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

DEPRECATED_LAMBDA_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x",
    "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet6",
    "ruby2.5", "ruby2.7", "ruby3.2",
    "java8", "go1.x", "provided",
}

# Read-only action prefixes that AWS legitimately requires Resource: "*" for.
READ_ONLY_ACTION_PREFIXES = ("describe", "list", "get", "head", "batchget", "lookup")

# Condition keys that genuinely scope cross-account or wildcard statements.
STRONG_SCOPING_CONDITION_KEYS = {
    "aws:principalorgid",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourceip",
    "sts:externalid",
}

# Explicit 10-service Resource Coverage Matrix (single source of truth).
SERVICE_COVERAGE_MATRIX = [
    {
        "service": "EC2",
        "scope": "Regional (all enabled regions)",
        "resource_types": [
            {"key": "ec2_instances", "type": "ec2_instance", "label": "EC2 Instances"},
            {"key": "elastic_ips", "type": "elastic_ip", "label": "Elastic IPs"},
            {"key": "security_groups", "type": "security_group", "label": "Security Groups"},
        ],
        "checks": ["EC2-001", "EC2-002", "EIP-001", "SG-001", "SG-002", "SG-003", "SG-004"],
    },
    {
        "service": "VPC",
        "scope": "Regional (all enabled regions)",
        "resource_types": [
            {"key": "vpcs", "type": "vpc", "label": "VPCs"},
            {"key": "internet_gateways", "type": "internet_gateway", "label": "Internet Gateways"},
            {"key": "nat_gateways", "type": "nat_gateway", "label": "NAT Gateways"},
        ],
        "checks": ["VPC-001", "IGW-001", "NAT-001", "NAT-002"],
    },
    {
        "service": "S3",
        "scope": "Global (mapped to actual bucket region)",
        "resource_types": [
            {"key": "s3_buckets", "type": "s3_bucket", "label": "S3 Buckets"},
        ],
        "checks": ["S3-002", "S3-003", "S3-004", "S3-005"],
    },
    {
        "service": "IAM",
        "scope": "Global",
        "resource_types": [
            {"key": "iam_roles", "type": "iam_role", "label": "IAM Roles"},
            {"key": "iam_users", "type": "iam_user", "label": "IAM Users"},
        ],
        "checks": [
            "IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005",
            "IAM-006", "IAM-007", "IAM-008", "IAM-009", "IAM-010", "IAM-011",
        ],
    },
    {
        "service": "Lambda",
        "scope": "Regional (all enabled regions)",
        "resource_types": [
            {"key": "lambda_functions", "type": "lambda_function", "label": "Lambda Functions"},
        ],
        "checks": ["LAM-001", "LAM-002"],
    },
    {
        "service": "RDS",
        "scope": "Regional (all enabled regions)",
        "resource_types": [
            {"key": "rds_instances", "type": "rds_instance", "label": "RDS DB Instances"},
        ],
        "checks": ["RDS-001", "RDS-002", "RDS-003", "RDS-004"],
    },
    {
        "service": "DynamoDB",
        "scope": "Regional (all enabled regions)",
        "resource_types": [
            {"key": "dynamodb_tables", "type": "dynamodb_table", "label": "DynamoDB Tables"},
        ],
        "checks": ["DDB-001", "DDB-002"],
    },
    {
        "service": "EBS",
        "scope": "Regional (all enabled regions)",
        "resource_types": [
            {"key": "ebs_volumes", "type": "ebs_volume", "label": "EBS Volumes"},
            {"key": "snapshots", "type": "ebs_snapshot", "label": "EBS Snapshots"},
        ],
        "checks": ["EBS-001", "EBS-002", "SNAP-001"],
    },
    {
        "service": "CloudWatch",
        "scope": "Regional (all enabled regions)",
        "resource_types": [
            {"key": "cloudwatch_alarms", "type": "cloudwatch_alarm", "label": "CloudWatch Alarms"},
            {"key": "cloudwatch_log_groups", "type": "cloudwatch_log_group", "label": "CloudWatch Log Groups"},
        ],
        "checks": ["CW-001", "CW-002", "CW-003"],
    },
    {
        "service": "CloudTrail",
        "scope": "Regional (deduplicated by home region)",
        "resource_types": [
            {"key": "cloudtrail_trails", "type": "cloudtrail_trail", "label": "CloudTrail Trails"},
        ],
        "checks": ["CT-001", "CT-002", "CT-003"],
    },
]

RULE_METADATA = {
    # ── EC2 ──────────────────────────────────────────────────────────────────
    "SG-001": {
        "name": "Unrestricted Inbound Traffic (All Ports)",
        "service": "EC2",
        "resource_type": "security_group",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether inbound firewall rules allow all protocols (-1) and all ports from 0.0.0.0/0 or ::/0.",
        "what_found": "Inbound firewall rule allows all protocols (-1) and all ports from 0.0.0.0/0 or ::/0.",
        "what_checked": "Evaluated Security Group ingress IP permissions for unrestricted CIDR routes across all protocols.",
    },
    "SG-002": {
        "name": "Unrestricted SSH Access (Port 22)",
        "service": "EC2",
        "resource_type": "security_group",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether inbound SSH (port 22) is exposed to 0.0.0.0/0 or ::/0.",
        "what_found": "Inbound SSH access is allowed from 0.0.0.0/0 or ::/0 on port 22.",
        "what_checked": "Evaluated Security Group ingress IP permissions for port 22 with unrestricted CIDR sources.",
    },
    "SG-003": {
        "name": "Unrestricted RDP Access (Port 3389)",
        "service": "EC2",
        "resource_type": "security_group",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether inbound Windows RDP (port 3389) is exposed to 0.0.0.0/0 or ::/0.",
        "what_found": "Inbound RDP access is allowed from 0.0.0.0/0 or ::/0 on port 3389.",
        "what_checked": "Evaluated Security Group ingress IP permissions for port 3389 with unrestricted CIDR sources.",
    },
    "SG-004": {
        "name": "Database Port Exposed to Internet",
        "service": "EC2",
        "resource_type": "security_group",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether common database ports (3306, 5432, 1433, 6379, 27017) are open to 0.0.0.0/0 or ::/0.",
        "what_found": "Inbound firewall rule exposes a database port directly to the public internet.",
        "what_checked": "Evaluated Security Group ingress port ranges against database ports with unrestricted CIDR sources.",
    },
    "EC2-001": {
        "name": "Stopped EC2 Instance (Review Attached Storage Costs)",
        "service": "EC2",
        "resource_type": "ec2_instance",
        "severity": "INFO",
        "category": "Potential Cost Waste",
        "what_it_checks": "Informational review noting whether an EC2 instance is stopped while retaining attached EBS storage or Elastic IPs (intentionally paused dev/scheduled instances are not marked unhealthy).",
        "what_found": "EC2 instance is in 'stopped' state while retaining attached storage and IPs.",
        "what_checked": "Inspected EC2 DescribeInstances instance state.",
    },
    "EC2-002": {
        "name": "IMDSv2 Not Enforced",
        "service": "EC2",
        "resource_type": "ec2_instance",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an active EC2 instance requires IMDSv2 (HttpTokens=required) to protect IAM credentials from SSRF.",
        "what_found": "EC2 instance still permits IMDSv1 (HttpTokens is not 'required').",
        "what_checked": "Inspected EC2 DescribeInstances MetadataOptions.HttpTokens attribute.",
    },
    "EIP-001": {
        "name": "Unassociated Elastic IP",
        "service": "EC2",
        "resource_type": "elastic_ip",
        "severity": "UNUSED",
        "category": "Potential Cost Waste",
        "what_it_checks": "Checks whether an allocated Elastic IP is unattached to any instance or ENI, incurring hourly public IPv4 charges.",
        "what_found": "Elastic IP address has no active AssociationId or attached network interface.",
        "what_checked": "Inspected EC2 DescribeAddresses AssociationId field.",
    },

    # ── VPC ──────────────────────────────────────────────────────────────────
    "VPC-001": {
        "name": "Publicly Exposed Workloads in Default VPC",
        "service": "VPC",
        "resource_type": "vpc",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether a default VPC actively hosts public-facing EC2 or publicly accessible RDS workloads (an empty default VPC is not flagged).",
        "what_found": "Active public-facing compute or database resources are deployed inside the default VPC.",
        "what_checked": "Cross-referenced default VPC ID against running public EC2 instances and publicly accessible RDS databases.",
    },
    "IGW-001": {
        "name": "Unattached Internet Gateway",
        "service": "VPC",
        "resource_type": "internet_gateway",
        "severity": "UNUSED",
        "category": "Operational Concern",
        "what_it_checks": "Checks whether an Internet Gateway exists without being attached to any VPC.",
        "what_found": "Internet Gateway exists with 0 VPC attachments.",
        "what_checked": "Inspected EC2 DescribeInternetGateways Attachments array.",
    },
    "NAT-001": {
        "name": "Failed NAT Gateway",
        "service": "VPC",
        "resource_type": "nat_gateway",
        "severity": "WARNING",
        "category": "Operational Concern",
        "what_it_checks": "Checks whether a NAT Gateway is in a failed state and unable to route private subnet traffic.",
        "what_found": "NAT Gateway is in a failed state.",
        "what_checked": "Inspected EC2 DescribeNatGateways State attribute.",
    },
    "NAT-002": {
        "name": "Active NAT Gateway (Review Ongoing Cost)",
        "service": "VPC",
        "resource_type": "nat_gateway",
        "severity": "INFO",
        "category": "Potential Cost Waste",
        "what_it_checks": "Informational cost review for active NAT Gateways because they incur continuous hourly and per-GB data-processing charges.",
        "what_found": "NAT Gateway is active and incurs ongoing hourly and data-processing charges.",
        "what_checked": "Inspected EC2 DescribeNatGateways State and SubnetId.",
    },

    # ── S3 ───────────────────────────────────────────────────────────────────
    "S3-002": {
        "name": "Public Access via Bucket Policy",
        "service": "S3",
        "resource_type": "s3_bucket",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an S3 bucket policy permits public read or write access.",
        "what_found": "Bucket policy explicitly allows public access from the internet.",
        "what_checked": "Queried S3 GetBucketPolicyStatus API.",
    },
    "S3-003": {
        "name": "Public Access via Bucket ACL",
        "service": "S3",
        "resource_type": "s3_bucket",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an S3 bucket ACL grants public access to AllUsers or AuthenticatedUsers.",
        "what_found": "Bucket ACL grants permissions to AllUsers or AuthenticatedUsers.",
        "what_checked": "Queried S3 GetBucketAcl API and inspected grantee URIs.",
    },
    "S3-004": {
        "name": "S3 Default Encryption Verification (SSE-S3 Active by Default)",
        "service": "S3",
        "resource_type": "s3_bucket",
        "severity": "INFO",
        "category": "Security Risk",
        "what_it_checks": "Informational verification that S3 bucket encryption metadata is readable (AWS enforces SSE-S3 encryption by default on all buckets since Jan 2023; never raises false encryption warnings).",
        "what_found": "Inspected bucket encryption configuration; AWS S3 applies SSE-S3 by default.",
        "what_checked": "Queried S3 GetBucketEncryption and accounted for AWS default SSE-S3 encryption.",
    },
    "S3-005": {
        "name": "Incomplete Block Public Access",
        "service": "S3",
        "resource_type": "s3_bucket",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether all 4 S3 Block Public Access controls are enabled.",
        "what_found": "One or more of the four S3 Block Public Access controls are disabled.",
        "what_checked": "Queried S3 GetPublicAccessBlock configuration for all 4 flags.",
    },

    # ── IAM ──────────────────────────────────────────────────────────────────
    "IAM-001": {
        "name": "Unrestricted Admin Wildcard Policy",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an inline role policy grants Action: *, iam:*, or NotAction on Resource: * without scoping conditions.",
        "what_found": "Inline IAM policy grants unrestricted administrative wildcard permissions.",
        "what_checked": "Evaluated role inline policy statements across Action/NotAction, Resource, and Condition context.",
    },
    "IAM-002": {
        "name": "Unscoped Write/Destructive Actions on Resource: *",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether non-read-only write/mutate actions apply to Resource: * without scoping conditions (read-only Describe/List/Get actions are excluded).",
        "what_found": "Inline IAM policy grants write or state-changing actions across Resource: * without scoping conditions.",
        "what_checked": "Evaluated inline policy statements distinguishing write/destructive actions from read-only discovery actions and checking Conditions.",
    },
    "IAM-003": {
        "name": "AdministratorAccess Managed Policy Attached",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether AWS-managed AdministratorAccess is attached to a customer-managed IAM role.",
        "what_found": "AWS managed policy AdministratorAccess is attached to this role.",
        "what_checked": "Inspected IAM ListAttachedRolePolicies (excluding AWS service-linked roles).",
    },
    "IAM-004": {
        "name": "IAMFullAccess Managed Policy Attached",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether IAMFullAccess is attached to a customer-managed IAM role.",
        "what_found": "AWS managed policy IAMFullAccess is attached to this role.",
        "what_checked": "Inspected IAM ListAttachedRolePolicies for IAMFullAccess.",
    },
    "IAM-005": {
        "name": "Unrestricted Public Role Trust Policy",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an IAM role trust policy allows Principal: * or AWS: * without strong scoping conditions.",
        "what_found": "Role trust policy allows unrestricted wildcard principals without scoping conditions.",
        "what_checked": "Parsed AssumeRolePolicyDocument Principal and Condition blocks.",
    },
    "IAM-006": {
        "name": "Unscoped Service-Wide Wildcard Actions",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether inline policies grant full service wildcards (e.g. s3:*, ec2:*) on Resource: * without scoping conditions.",
        "what_found": "Inline policy grants full service wildcard actions on Resource: * without conditions.",
        "what_checked": "Evaluated inline policy Action wildcards, Resource scope, and Condition blocks.",
    },
    "IAM-007": {
        "name": "PowerUserAccess Managed Policy Attached",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether PowerUserAccess is attached to a customer-managed IAM role.",
        "what_found": "AWS managed policy PowerUserAccess is attached to this role.",
        "what_checked": "Inspected IAM ListAttachedRolePolicies for PowerUserAccess.",
    },
    "IAM-008": {
        "name": "Cross-Account Trust Missing ExternalId / Org Condition",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether external cross-account trust policies enforce sts:ExternalId or aws:PrincipalOrgID.",
        "what_found": "Cross-account trust relationship lacks sts:ExternalId and aws:PrincipalOrgID conditions.",
        "what_checked": "Inspected AssumeRolePolicyDocument external account principals against current account ID and Condition blocks.",
    },
    "IAM-009": {
        "name": "IAM User Missing MFA",
        "service": "IAM",
        "resource_type": "iam_user",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an IAM user with console sign-in activity or administrative access has MFA enabled.",
        "what_found": "IAM user with console or privileged access has 0 MFA devices registered.",
        "what_checked": "Inspected IAM ListUsers PasswordLastUsed, attached policies, and ListMFADevices.",
    },
    "IAM-010": {
        "name": "Long-Lived Active IAM Access Key (>90 Days)",
        "service": "IAM",
        "resource_type": "iam_user",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an IAM user has an Active static access key older than 90 days (age alone does not indicate compromise, but rotation reduces risk).",
        "what_found": "IAM user has an Active static access key older than 90 days.",
        "what_checked": "Inspected IAM ListAccessKeys status and CreateDate.",
    },
    "IAM-011": {
        "name": "IAM User Directly Attached AdministratorAccess",
        "service": "IAM",
        "resource_type": "iam_user",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an IAM user has AdministratorAccess or wildcard Action: * attached directly.",
        "what_found": "IAM user has full administrative permissions attached directly to the user.",
        "what_checked": "Inspected IAM ListAttachedUserPolicies and inline user policies.",
    },

    # ── Lambda ───────────────────────────────────────────────────────────────
    "LAM-001": {
        "name": "Lambda Function Unmodified >90 Days (Review)",
        "service": "Lambda",
        "resource_type": "lambda_function",
        "severity": "INFO",
        "category": "Operational Concern",
        "what_it_checks": "Informational check noting whether a Lambda function has not been updated in over 90 days (stable functions are not automatically unhealthy).",
        "what_found": "Function has not been modified in over 90 days.",
        "what_checked": "Inspected Lambda ListFunctions LastModified timestamp.",
    },
    "LAM-002": {
        "name": "Deprecated Lambda Runtime",
        "service": "Lambda",
        "resource_type": "lambda_function",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether a Lambda function uses an end-of-life runtime that no longer receives AWS security patches.",
        "what_found": "Lambda function uses a deprecated runtime.",
        "what_checked": "Inspected Lambda ListFunctions Runtime attribute.",
    },

    # ── RDS ──────────────────────────────────────────────────────────────────
    "RDS-001": {
        "name": "Publicly Accessible RDS Database",
        "service": "RDS",
        "resource_type": "rds_instance",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an RDS instance has PubliclyAccessible enabled.",
        "what_found": "RDS instance PubliclyAccessible flag is set to true.",
        "what_checked": "Inspected RDS DescribeDBInstances PubliclyAccessible attribute.",
    },
    "RDS-002": {
        "name": "RDS Storage Unencrypted",
        "service": "RDS",
        "resource_type": "rds_instance",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an RDS database storage volume is encrypted at rest.",
        "what_found": "RDS instance storage encryption is disabled.",
        "what_checked": "Inspected RDS DescribeDBInstances StorageEncrypted attribute.",
    },
    "RDS-003": {
        "name": "RDS Deletion Protection Disabled",
        "service": "RDS",
        "resource_type": "rds_instance",
        "severity": "WARNING",
        "category": "Operational Concern",
        "what_it_checks": "Checks whether accidental deletion protection is enabled on RDS databases.",
        "what_found": "Deletion protection is disabled on this RDS instance.",
        "what_checked": "Inspected RDS DescribeDBInstances DeletionProtection attribute.",
    },
    "RDS-004": {
        "name": "RDS Automated Backups Disabled",
        "service": "RDS",
        "resource_type": "rds_instance",
        "severity": "WARNING",
        "category": "Operational Concern",
        "what_it_checks": "Checks whether RDS automated backups are disabled (BackupRetentionPeriod = 0).",
        "what_found": "RDS automated backup retention period is set to 0 days.",
        "what_checked": "Inspected RDS DescribeDBInstances BackupRetentionPeriod attribute.",
    },

    # ── DynamoDB ─────────────────────────────────────────────────────────────
    "DDB-001": {
        "name": "DynamoDB Encryption Disabled",
        "service": "DynamoDB",
        "resource_type": "dynamodb_table",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether a DynamoDB table explicitly reports encryption disabled (AWS-owned default encryption passes).",
        "what_found": "DynamoDB table explicitly reports encryption at rest disabled.",
        "what_checked": "Inspected DynamoDB DescribeTable SSEDescription (respecting AWS-owned default encryption).",
    },
    "DDB-002": {
        "name": "Empty Provisioned DynamoDB Table (Review Capacity Mode)",
        "service": "DynamoDB",
        "resource_type": "dynamodb_table",
        "severity": "INFO",
        "category": "Potential Cost Waste",
        "what_it_checks": "Informational review noting whether a PROVISIONED-capacity DynamoDB table reports 0 items (AWS updates ItemCount roughly every 6 hours, and staging/free-tier tables may be intentionally provisioned).",
        "what_found": "DynamoDB table uses PROVISIONED billing mode while reporting 0 items.",
        "what_checked": "Inspected DynamoDB DescribeTable BillingModeSummary and ItemCount.",
    },

    # ── EBS ──────────────────────────────────────────────────────────────────
    "EBS-001": {
        "name": "EBS Volume Unencrypted",
        "service": "EBS",
        "resource_type": "ebs_volume",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether an EBS volume is encrypted at rest.",
        "what_found": "EBS volume block storage has encryption disabled.",
        "what_checked": "Inspected EC2 DescribeVolumes Encrypted attribute.",
    },
    "EBS-002": {
        "name": "Unattached EBS Volume",
        "service": "EBS",
        "resource_type": "ebs_volume",
        "severity": "UNUSED",
        "category": "Potential Cost Waste",
        "what_it_checks": "Checks whether an EBS volume is in 'available' state (unattached) and accumulating monthly storage charges.",
        "what_found": "EBS volume is in 'available' state and not attached to any EC2 instance.",
        "what_checked": "Inspected EC2 DescribeVolumes State and Attachments.",
    },
    "SNAP-001": {
        "name": "EBS Snapshot Without Original Volume (Review)",
        "service": "EBS",
        "resource_type": "ebs_snapshot",
        "severity": "INFO",
        "category": "Potential Cost Waste",
        "what_it_checks": "Informational review for snapshots whose original EBS volume no longer exists (may be intentional backups or AMI snapshots).",
        "what_found": "The original EBS volume for this snapshot no longer exists in the region.",
        "what_checked": "Cross-referenced Snapshot VolumeId against active EBS volumes in the region.",
    },

    # ── CloudWatch ───────────────────────────────────────────────────────────
    "CW-001": {
        "name": "CloudWatch Alarm Actions Disabled",
        "service": "CloudWatch",
        "resource_type": "cloudwatch_alarm",
        "severity": "WARNING",
        "category": "Operational Concern",
        "what_it_checks": "Checks whether a CloudWatch alarm has alarm actions disabled.",
        "what_found": "CloudWatch alarm has ActionsEnabled set to false.",
        "what_checked": "Inspected CloudWatch DescribeAlarms ActionsEnabled flag.",
    },
    "CW-002": {
        "name": "CloudWatch Alarm in INSUFFICIENT_DATA State (Review)",
        "service": "CloudWatch",
        "resource_type": "cloudwatch_alarm",
        "severity": "INFO",
        "category": "Operational Concern",
        "what_it_checks": "Informational check noting whether an alarm is currently in INSUFFICIENT_DATA (normal for sparse metrics or new alarms; not automatically a failure).",
        "what_found": "CloudWatch alarm state is currently INSUFFICIENT_DATA.",
        "what_checked": "Inspected CloudWatch DescribeAlarms StateValue attribute.",
    },
    "CW-003": {
        "name": "CloudWatch Log Group Set to Never Expire",
        "service": "CloudWatch",
        "resource_type": "cloudwatch_log_group",
        "severity": "WARNING",
        "category": "Potential Cost Waste",
        "what_it_checks": "Checks whether a CloudWatch Log Group has no retention policy, allowing stored logs and storage charges to grow indefinitely.",
        "what_found": "CloudWatch Log Group has no retention period configured (Never Expire).",
        "what_checked": "Inspected CloudWatch Logs DescribeLogGroups retentionInDays and storedBytes.",
    },

    # ── CloudTrail ───────────────────────────────────────────────────────────
    "CT-001": {
        "name": "CloudTrail Trail Logging Disabled",
        "service": "CloudTrail",
        "resource_type": "cloudtrail_trail",
        "severity": "CRITICAL",
        "category": "Security Risk",
        "what_it_checks": "Checks whether a CloudTrail trail has logging actively turned on.",
        "what_found": "CloudTrail trail has IsLogging set to false.",
        "what_checked": "Inspected CloudTrail GetTrailStatus IsLogging flag.",
    },
    "CT-002": {
        "name": "CloudTrail Trail Not Multi-Region",
        "service": "CloudTrail",
        "resource_type": "cloudtrail_trail",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether a CloudTrail trail captures API activity across all AWS regions.",
        "what_found": "CloudTrail trail is restricted to a single region (IsMultiRegionTrail=false).",
        "what_checked": "Inspected CloudTrail DescribeTrails IsMultiRegionTrail attribute.",
    },
    "CT-003": {
        "name": "CloudTrail Log File Validation Disabled",
        "service": "CloudTrail",
        "resource_type": "cloudtrail_trail",
        "severity": "WARNING",
        "category": "Security Risk",
        "what_it_checks": "Checks whether CloudTrail cryptographic log file integrity validation is enabled.",
        "what_found": "CloudTrail log file integrity validation is disabled.",
        "what_checked": "Inspected CloudTrail DescribeTrails LogFileValidationEnabled attribute.",
    },
}

CHECKS_BY_RESOURCE = {
    "ec2_instances": ["EC2-001", "EC2-002"],
    "elastic_ips": ["EIP-001"],
    "security_groups": ["SG-001", "SG-002", "SG-003", "SG-004"],
    "vpcs": ["VPC-001"],
    "internet_gateways": ["IGW-001"],
    "nat_gateways": ["NAT-001", "NAT-002"],
    "s3_buckets": ["S3-002", "S3-003", "S3-004", "S3-005"],
    "iam_roles": ["IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005", "IAM-006", "IAM-007", "IAM-008"],
    "iam_users": ["IAM-009", "IAM-010", "IAM-011"],
    "lambda_functions": ["LAM-001", "LAM-002"],
    "rds_instances": ["RDS-001", "RDS-002", "RDS-003", "RDS-004"],
    "dynamodb_tables": ["DDB-001", "DDB-002"],
    "ebs_volumes": ["EBS-001", "EBS-002"],
    "snapshots": ["SNAP-001"],
    "cloudwatch_alarms": ["CW-001", "CW-002"],
    "cloudwatch_log_groups": ["CW-003"],
    "cloudtrail_trails": ["CT-001", "CT-002", "CT-003"],
}

RULE_REQUIRED_FIELDS = {
    "EC2-001": ("state",),
    "EC2-002": ("state", "http_tokens"),
    "EIP-001": ("association_id",),
    "SG-001": ("ip_permissions",),
    "SG-002": ("ip_permissions",),
    "SG-003": ("ip_permissions",),
    "SG-004": ("ip_permissions",),
    "VPC-001": ("is_default",),
    "IGW-001": ("attachments",),
    "NAT-001": ("state",),
    "NAT-002": ("state",),
    "S3-002": ("name",),
    "S3-003": ("name",),
    "S3-004": ("name",),
    "S3-005": ("name",),
    "IAM-001": ("inline_policies",),
    "IAM-002": ("inline_policies",),
    "IAM-003": ("attached_managed_policies",),
    "IAM-004": ("attached_managed_policies",),
    "IAM-005": ("trust_policy",),
    "IAM-006": ("inline_policies",),
    "IAM-007": ("attached_managed_policies",),
    "IAM-008": ("trust_policy",),
    "IAM-009": ("mfa_devices_count",),
    "IAM-010": ("access_keys",),
    "IAM-011": ("attached_managed_policies", "inline_policies"),
    "LAM-001": ("last_modified",),
    "LAM-002": ("runtime",),
    "RDS-001": ("publicly_accessible",),
    "RDS-002": ("storage_encrypted",),
    "RDS-003": ("deletion_protection",),
    "RDS-004": ("backup_retention_period",),
    "DDB-001": ("sse_description",),
    "DDB-002": ("billing_mode", "item_count"),
    "EBS-001": ("encrypted",),
    "EBS-002": ("state",),
    "SNAP-001": ("volume_id",),
    "CW-001": ("actions_enabled",),
    "CW-002": ("state_value",),
    "CW-003": ("retention_in_days",),
    "CT-001": ("is_logging",),
    "CT-002": ("is_multi_region_trail",),
    "CT-003": ("log_file_validation_enabled",),
}

# AWS APIs where None is genuine, inspected evidence ("not configured").
NULL_IS_EVIDENCE = {
    "EIP-001": {"association_id"},
    "CW-003": {"retention_in_days"},
}


def get_rules_catalog() -> list[dict]:
    return [
        {
            "id": rule_id,
            "name": meta["name"],
            "service": meta["service"],
            "resourceType": meta["resource_type"],
            "severity": meta["severity"],
            "category": meta["category"],
            "whatItChecks": meta["what_it_checks"],
        }
        for rule_id, meta in RULE_METADATA.items()
    ]


def _extract_account_from_principal(principal_str: str) -> str | None:
    if not isinstance(principal_str, str):
        return None
    if principal_str.isdigit() and len(principal_str) == 12:
        return principal_str
    match = re.match(r"^arn:aws:iam::(\d{12}):", principal_str)
    return match.group(1) if match else None


def _has_strong_condition(statement: dict) -> bool:
    condition = statement.get("Condition")
    if not isinstance(condition, dict) or not condition:
        return False
    for _, cond_map in condition.items():
        if not isinstance(cond_map, dict):
            continue
        for key in cond_map.keys():
            lowered = str(key).lower()
            if lowered in STRONG_SCOPING_CONDITION_KEYS or lowered.startswith("aws:resourcetag/"):
                return True
    return False


def _is_read_only_action(action: str) -> bool:
    if not isinstance(action, str) or ":" not in action:
        return False
    _, op = action.split(":", 1)
    lowered = op.lower()
    if lowered == "*":
        return False
    return lowered.startswith(READ_ONLY_ACTION_PREFIXES)


def _missing_rule_fields(raw: dict, rule_id: str) -> list[str]:
    if rule_id == "DDB-001":
        description = raw.get("sse_description")
        if isinstance(description, dict) and description.get("Status") in ("ENABLED", "DISABLED"):
            return []
        return ["sse_description.Status"]

    if rule_id == "EC2-002":
        if str(raw.get("state", "")).lower() == "terminated":
            return []
        if raw.get("http_tokens") is None:
            return ["http_tokens"]
        return []

    if rule_id == "LAM-002":
        if raw.get("package_type") == "Image":
            return []
        if not raw.get("runtime"):
            return ["runtime"]
        return []

    return [
        field
        for field in RULE_REQUIRED_FIELDS.get(rule_id, ())
        if field not in raw
        or (raw[field] is None and field not in NULL_IS_EVIDENCE.get(rule_id, set()))
    ]


def _has_rule_evidence(raw: dict, rule_id: str) -> bool:
    return not _missing_rule_fields(raw, rule_id)


def _assessment(rule_ids: list[str], raw: dict, issues: list[dict], rule_errors: dict | None = None) -> dict:
    """Return explicit per-rule evaluation states (PASSED / REVIEW / VIOLATED / CHECK_FAILED)."""
    rule_errors = rule_errors or {}
    results = []
    for rule_id in rule_ids:
        missing = _missing_rule_fields(raw, rule_id)
        matching_issues = [issue for issue in issues if issue.get("rule_id") == rule_id]
        if rule_id in rule_errors:
            status = "CHECK_FAILED"
            reason = rule_errors[rule_id]
        elif missing:
            status = "CHECK_FAILED"
            reason = "Missing required AWS configuration field(s): " + ", ".join(missing)
        elif any(issue.get("severity") != "INFO" for issue in matching_issues):
            status, reason = "VIOLATED", None
        elif matching_issues:
            status, reason = "REVIEW", None
        else:
            status, reason = "PASSED", None
        check = {"rule_id": rule_id, "status": status}
        if reason:
            check["reason"] = reason
        results.append(check)

    failed_count = sum(item["status"] == "CHECK_FAILED" for item in results)
    return {
        "status": "INCOMPLETE" if failed_count > 0 else "COMPLETE",
        "checks": results,
    }


def _issue(
    rule_id: str,
    severity: str,
    title: str,
    why: str,
    evidence: dict,
    fix: str,
    verify: str,
    resource: dict | None = None,
    what_found: str | None = None,
    what_checked: str | None = None,
    category: str | None = None,
) -> dict:
    meta = RULE_METADATA.get(rule_id, {})
    item = {
        "rule_id": rule_id,
        "severity": severity,
        "category": category or meta.get("category") or "Security Risk",
        "title": title,
        "what_found": what_found or meta.get("what_found") or title,
        "why": why,
        "what_checked": what_checked or meta.get("what_checked") or "Inspected AWS resource configuration.",
        "evidence": evidence,
        "fix": fix,
        "verify": verify,
        "source": "AWS API configuration",
        "message": title,
    }
    if resource:
        item["resource_type"] = resource.get("type")
        item["resource_id"] = resource.get("id")
        item["resource_name"] = resource.get("name")
        item["region"] = resource.get("region")
        item["service"] = resource.get("service") or meta.get("service")
    return item


def _parse_datetime(value) -> datetime.datetime | None:
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    try:
        if "+" in value:
            time_part = value.split("+")[0]
            return datetime.datetime.strptime(time_part, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)
        if value.endswith("Z"):
            return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.datetime.fromisoformat(value)
    except Exception:
        return None


def evaluate(
    session,
    resources: dict,
    account_id: str | None = None,
    scanner_statuses: list[dict] | None = None,
) -> dict:
    total = sum(len(v) for v in resources.values() if isinstance(v, list))
    if total == 0:
        return resources

    # Cache regional S3 clients so non-us-east-1 buckets never trigger PermanentRedirect
    s3_clients = {}

    def get_s3_client(region_name: str | None):
        if session is None:
            return None
        key = region_name if region_name and region_name != "global" else "us-east-1"
        if key not in s3_clients:
            s3_clients[key] = session.client("s3", region_name=key)
        return s3_clients[key]

    # Parallelize all S3 bucket security API checks (policy status, ACL, encryption, PAB)
    # across all buckets at once so S3 evaluation runs in ~1 RTT instead of 4 * N sequential calls.
    s3_prefetched: dict[str, dict] = {}
    s3_items = resources.get("s3_buckets") or []
    if session is not None and s3_items:
        # Pre-create needed regional S3 clients on the main thread
        bucket_clients = {
            r["id"]: get_s3_client(r.get("region"))
            for r in s3_items
            if isinstance(r, dict) and r.get("id")
        }

        def _fetch_s3_check(bucket_name: str, check_name: str):
            client = bucket_clients.get(bucket_name)
            if client is None:
                return (bucket_name, check_name, None, "S3 client unavailable")
            try:
                if check_name == "policy_status":
                    return (bucket_name, check_name, client.get_bucket_policy_status(Bucket=bucket_name), None)
                if check_name == "acl":
                    return (bucket_name, check_name, client.get_bucket_acl(Bucket=bucket_name), None)
                if check_name == "encryption":
                    return (bucket_name, check_name, client.get_bucket_encryption(Bucket=bucket_name), None)
                if check_name == "pab":
                    return (bucket_name, check_name, client.get_public_access_block(Bucket=bucket_name), None)
            except ClientError as e:
                return (bucket_name, check_name, None, e)
            except Exception as e:
                return (bucket_name, check_name, None, e)
            return (bucket_name, check_name, None, None)

        tasks = [
            (bname, chk)
            for bname in bucket_clients
            for chk in ("policy_status", "acl", "encryption", "pab")
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(24, len(tasks))) as ex:
            futs = [ex.submit(_fetch_s3_check, bname, chk) for bname, chk in tasks]
            for fut in concurrent.futures.as_completed(futs):
                bname, chk, resp, err = fut.result()
                s3_prefetched.setdefault(bname, {})[chk] = (resp, err)

    # Precompute cross-resource context
    failed_ebs_regions = {
        s.get("region")
        for s in (scanner_statuses or [])
        if s.get("key") == "ebs_volumes" and s.get("status") != "COMPLETED"
    }
    active_volume_ids = {v["id"] for v in resources.get("ebs_volumes", [])}

    # Track public-facing workloads inside VPCs so default VPCs are ONLY flagged when actively exposed
    public_workloads_by_vpc: dict[str, list[str]] = {}
    for inst in resources.get("ec2_instances", []):
        raw_i = inst.get("raw") or {}
        if str(raw_i.get("state", "")).lower() != "terminated" and raw_i.get("public_ip") and raw_i.get("vpc_id"):
            public_workloads_by_vpc.setdefault(raw_i["vpc_id"], []).append(f"EC2:{inst['id']}")
    for db in resources.get("rds_instances", []):
        raw_db = db.get("raw") or {}
        if raw_db.get("publicly_accessible") is True and raw_db.get("vpc_id"):
            public_workloads_by_vpc.setdefault(raw_db["vpc_id"], []).append(f"RDS:{db['id']}")

    for r_type, items in resources.items():
        if not isinstance(items, list):
            continue
        for r in items:
            raw = r.get("raw") if isinstance(r.get("raw"), dict) else {}
            rule_errors = dict(r.get("assessment_errors") or raw.get("_assessment_errors") or {})
            rule_ids = CHECKS_BY_RESOURCE.get(r_type, [])

            if not rule_ids or not raw:
                r["status"] = "INCOMPLETE"
                r["issues"] = []
                r["assessment"] = _assessment(rule_ids, raw, [], rule_errors)
                continue

            issues = []

            # ------------------------------------------------------------------
            # S3 Buckets
            # ------------------------------------------------------------------
            if r_type == "s3_buckets":
                bucket_name = r["id"]
                s3_client = get_s3_client(r.get("region"))

                if s3_client is None:
                    for rid in ("S3-002", "S3-003", "S3-004", "S3-005"):
                        rule_errors.setdefault(rid, "S3 client unavailable during evaluation")
                else:
                    prefetched = s3_prefetched.get(bucket_name, {})

                    pol_resp, pol_err = prefetched.get("policy_status", (None, None))
                    if pol_err is not None:
                        if isinstance(pol_err, ClientError):
                            code = pol_err.response.get("Error", {}).get("Code", "AWS error")
                            if code != "NoSuchBucketPolicy":
                                rule_errors["S3-002"] = f"Could not read bucket policy status: {code}"
                        else:
                            rule_errors["S3-002"] = f"Could not read bucket policy status: {pol_err}"
                    elif pol_resp and pol_resp.get("PolicyStatus", {}).get("IsPublic", False):
                        issues.append(_issue(
                            rule_id="S3-002",
                            severity="CRITICAL",
                            title="S3 bucket is publicly accessible via bucket policy",
                            why="Anyone on the internet can read or write objects depending on the policy statement.",
                            evidence={"Bucket": bucket_name, "AccessSource": "Bucket Policy", "IsPublic": "True"},
                            fix="Open S3 → Bucket → Permissions → Bucket policy, remove Principal: '*' statements (or restrict via CloudFront OAC / VPC conditions), and enable Block Public Access.",
                            verify="Confirm 'Publicly accessible' badge disappears in S3 Console, then click Re-scan in AWS Clarity to verify S3-002 resolves.",
                            resource=r,
                        ))

                    acl_resp, acl_err = prefetched.get("acl", (None, None))
                    if acl_err is not None:
                        if isinstance(acl_err, ClientError):
                            code = acl_err.response.get("Error", {}).get("Code", "AWS error")
                            rule_errors["S3-003"] = f"Could not read bucket ACL: {code}"
                        else:
                            rule_errors["S3-003"] = f"Could not read bucket ACL: {acl_err}"
                    elif acl_resp:
                        public_grantees = {
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                        }
                        public_grants = [
                            g.get("Grantee", {}).get("URI", "")
                            for g in acl_resp.get("Grants", [])
                            if g.get("Grantee", {}).get("URI") in public_grantees
                        ]
                        if public_grants:
                            issues.append(_issue(
                                rule_id="S3-003",
                                severity="CRITICAL",
                                title="S3 bucket ACL grants public access",
                                why="Public ACL grants allow anonymous or any AWS authenticated user to access the bucket.",
                                evidence={"Bucket": bucket_name, "AccessSource": "ACL", "PublicGrantees": ", ".join(public_grants)},
                                fix="Open S3 → Bucket → Permissions → Object Ownership → enable 'Bucket owner enforced' (disables ACLs), or remove public grants from the ACL.",
                                verify="Run a new AWS Clarity scan and verify S3-003 moves to Resolved.",
                                resource=r,
                            ))

                    _, enc_err = prefetched.get("encryption", (None, None))
                    if enc_err is not None:
                        if isinstance(enc_err, ClientError):
                            code = enc_err.response.get("Error", {}).get("Code", "AWS error")
                            if code != "ServerSideEncryptionConfigurationNotFoundError":
                                rule_errors["S3-004"] = f"Could not read bucket encryption configuration: {code}"
                        else:
                            rule_errors["S3-004"] = f"Could not read bucket encryption configuration: {enc_err}"

                    pab_resp, pab_err = prefetched.get("pab", (None, None))
                    if pab_err is not None:
                        if isinstance(pab_err, ClientError):
                            code = pab_err.response.get("Error", {}).get("Code", "AWS error")
                            if code == "NoSuchPublicAccessBlockConfiguration":
                                issues.append(_issue(
                                    rule_id="S3-005",
                                    severity="WARNING",
                                    title="S3 Block Public Access is not configured",
                                    why="Without Block Public Access enabled, a future policy or ACL change can expose bucket contents publicly.",
                                    evidence={"Bucket": bucket_name, "DisabledSettings": "All four settings not configured"},
                                    fix="Open S3 → Bucket → Permissions → Block public access → Edit and enable all four settings.",
                                    verify="Re-scan in AWS Clarity and confirm S3-005 passes.",
                                    resource=r,
                                ))
                            else:
                                rule_errors["S3-005"] = f"Could not read Block Public Access settings: {code}"
                        else:
                            rule_errors["S3-005"] = f"Could not read Block Public Access settings: {pab_err}"
                    elif pab_resp:
                        config = pab_resp.get("PublicAccessBlockConfiguration", {})
                        missing_pab = [
                            k
                            for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
                            if not config.get(k, False)
                        ]
                        if missing_pab:
                            issues.append(_issue(
                                rule_id="S3-005",
                                severity="WARNING",
                                title="S3 Block Public Access is not fully enabled",
                                why="Disabling any Block Public Access guardrail leaves the bucket vulnerable to accidental future policy or ACL exposure.",
                                evidence={"Bucket": bucket_name, "DisabledSettings": ", ".join(missing_pab)},
                                fix="Open S3 → Bucket → Permissions → Block public access → Edit and enable all four settings.",
                                verify="Re-scan in AWS Clarity and confirm S3-005 passes on this bucket.",
                                resource=r,
                            ))

            # ------------------------------------------------------------------
            # Security Groups (EC2)
            # ------------------------------------------------------------------
            elif r_type == "security_groups":
                dangerous_cidrs = {"0.0.0.0/0", "::/0"}
                for rule in raw.get("ip_permissions", []):
                    protocol = rule.get("IpProtocol")
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    cidrs = [route.get("CidrIp") for route in rule.get("IpRanges", [])]
                    cidrs += [route.get("CidrIpv6") for route in rule.get("Ipv6Ranges", [])]

                    for cidr in cidrs:
                        if cidr not in dangerous_cidrs:
                            continue
                        proto_label = "All protocols" if protocol == "-1" else str(protocol).upper()

                        if protocol == "-1":
                            issues.append(_issue(
                                rule_id="SG-001",
                                severity="CRITICAL",
                                title="Security group allows all inbound traffic from the internet",
                                why="Allowing all protocols and ports from the internet exposes every listening service on attached resources.",
                                evidence={"SecurityGroup": r["id"], "Protocol": "All", "Ports": "All", "Source": cidr},
                                fix="Open EC2 → Security Groups → Inbound rules, remove the 'All traffic' rule from 0.0.0.0/0 (or ::/0), and allow only required ports/CIDRs.",
                                verify="Inspect inbound rules in EC2 Console and re-scan in AWS Clarity to confirm SG-001 is resolved.",
                                resource=r,
                            ))
                        elif from_port is not None and to_port is not None:
                            if from_port <= 22 <= to_port:
                                port_range = "22" if from_port == to_port else f"{from_port}-{to_port}"
                                issues.append(_issue(
                                    rule_id="SG-002",
                                    severity="CRITICAL",
                                    title="SSH (port 22) open to the internet",
                                    why="Publicly exposed SSH invites continuous brute-force and credential-stuffing attacks.",
                                    evidence={"SecurityGroup": r["id"], "Port": port_range, "Protocol": proto_label, "Source": cidr},
                                    fix="Edit inbound rules to restrict port 22 to your specific IP/VPN CIDR, or remove port 22 and use AWS Systems Manager Session Manager.",
                                    verify="Confirm no inbound rule allows port 22 from 0.0.0.0/0 or ::/0, then re-scan in AWS Clarity.",
                                    resource=r,
                                ))
                            if from_port <= 3389 <= to_port:
                                port_range = "3389" if from_port == to_port else f"{from_port}-{to_port}"
                                issues.append(_issue(
                                    rule_id="SG-003",
                                    severity="CRITICAL",
                                    title="RDP (port 3389) open to the internet",
                                    why="Publicly exposed Remote Desktop is a primary ransomware and credential-compromise vector.",
                                    evidence={"SecurityGroup": r["id"], "Port": port_range, "Protocol": proto_label, "Source": cidr},
                                    fix="Restrict port 3389 to your organization's static IP/VPN CIDR or connect privately via AWS Systems Manager.",
                                    verify="Confirm port 3389 is no longer open to 0.0.0.0/0 or ::/0, then re-scan in AWS Clarity.",
                                    resource=r,
                                ))
                            exposed_db = [
                                f"{port} ({db_name})"
                                for port, db_name in SENSITIVE_DB_PORTS.items()
                                if from_port <= port <= to_port
                            ]
                            if exposed_db:
                                issues.append(_issue(
                                    rule_id="SG-004",
                                    severity="CRITICAL",
                                    title="Database port open to the internet",
                                    why="Database ports exposed to 0.0.0.0/0 allow external attackers to directly probe and attack your data tier.",
                                    evidence={"SecurityGroup": r["id"], "ExposedPorts": ", ".join(exposed_db), "Protocol": proto_label, "Source": cidr},
                                    fix="Change the inbound rule source from 0.0.0.0/0 (or ::/0) to the specific application security group ID or private VPC CIDR.",
                                    verify="Confirm database ports only accept traffic from private security groups/CIDRs, then re-scan in AWS Clarity.",
                                    resource=r,
                                ))

            # ------------------------------------------------------------------
            # EC2 Instances
            # ------------------------------------------------------------------
            elif r_type == "ec2_instances":
                ec2_state = str(raw.get("state", "")).lower()
                if ec2_state == "stopped":
                    issues.append(_issue(
                        rule_id="EC2-001",
                        severity="INFO",
                        title="Stopped EC2 instance (review attached EBS/EIP costs)",
                        why="A stopped instance is NOT automatically wasteful (dev, staging, or scheduled instances are often paused on purpose). Stopped instances do not incur EC2 compute charges, though attached EBS volumes and Elastic IPs continue generating monthly charges.",
                        evidence={
                            "Instance": r["id"],
                            "InstanceType": str(raw.get("instance_type") or "unknown"),
                            "State": "stopped",
                            "AttachedVolumes": str(len(raw.get("ebs_volumes") or [])),
                        },
                        fix="Verify whether this instance is paused intentionally (e.g., scheduled dev/staging server). Before terminating, confirm no data is needed or create an AMI/EBS snapshot backup, check IaC/Terraform state, and then terminate manually in EC2 → Instances.",
                        verify="Re-scan in AWS Clarity after restarting or terminating the instance and confirm EC2-001 resolves.",
                        resource=r,
                    ))

                http_tokens = raw.get("http_tokens")
                if ec2_state != "terminated" and http_tokens is not None and http_tokens != "required":
                    issues.append(_issue(
                        rule_id="EC2-002",
                        severity="WARNING",
                        title="EC2 instance does not enforce IMDSv2",
                        why="Allowing IMDSv1 makes instance IAM role credentials easier to exfiltrate via SSRF vulnerabilities.",
                        evidence={"Instance": r["id"], "HttpTokens": str(http_tokens), "Expected": "required"},
                        fix="Run `aws ec2 modify-instance-metadata-options --instance-id " + r["id"] + " --http-tokens required` or update via EC2 Console → Actions → Instance settings → Modify instance metadata options.",
                        verify="Verify `HttpTokens` is `required` in EC2 instance metadata options, then re-scan in AWS Clarity.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # Elastic IPs (EC2)
            # ------------------------------------------------------------------
            elif r_type == "elastic_ips":
                if not raw.get("association_id"):
                    issues.append(_issue(
                        rule_id="EIP-001",
                        severity="UNUSED",
                        title="Unassociated Elastic IP incurring hourly IPv4 charges",
                        why="AWS charges hourly for allocated public IPv4 addresses even when unattached to any running resource.",
                        evidence={"AllocationId": r["id"], "PublicIp": str(raw.get("public_ip") or "unknown"), "AssociationId": "None"},
                        fix="Confirm this static IP is not allowlisted by external partners, DNS A-records, or firewall rules (releasing an Elastic IP permanently forfeits the address). If confirmed unneeded, release it manually via EC2 → Elastic IPs → Actions → Release Elastic IP address.",
                        verify="Re-scan in AWS Clarity and confirm the Elastic IP no longer appears as unassociated.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # VPCs, Internet Gateways, NAT Gateways (VPC)
            # ------------------------------------------------------------------
            elif r_type == "vpcs":
                vpc_id = r["id"]
                exposed = public_workloads_by_vpc.get(vpc_id, [])
                # A default VPC existing by itself is NOT a security vulnerability;
                # only flag when active public-facing workloads are running inside it.
                if raw.get("is_default") is True and exposed:
                    issues.append(_issue(
                        rule_id="VPC-001",
                        severity="WARNING",
                        title="Public-facing workloads running inside the default VPC",
                        why="Default VPCs place all subnets directly on the public internet without private/public subnet isolation.",
                        evidence={
                            "VpcId": vpc_id,
                            "IsDefault": "True",
                            "CidrBlock": str(raw.get("cidr_block") or "unknown"),
                            "PublicWorkloads": ", ".join(exposed[:5]),
                        },
                        fix="Migrate production compute and database workloads into a custom VPC with isolated private subnets and explicit route tables.",
                        verify="Re-scan in AWS Clarity once public workloads are moved out of the default VPC and confirm VPC-001 passes.",
                        resource=r,
                    ))

            elif r_type == "internet_gateways":
                igw_id = r["id"]
                attachments = raw.get("attachments", [])
                if len(attachments) == 0:
                    issues.append(_issue(
                        rule_id="IGW-001",
                        severity="UNUSED",
                        title="Unattached Internet Gateway",
                        why="This Internet Gateway is detached from all VPCs and serves no active routing purpose (Internet Gateways have no hourly charge, but detached gateways add network clutter).",
                        evidence={"InternetGateway": igw_id, "Attachments": "0"},
                        fix="Verify no Terraform/CloudFormation stack manages this gateway for a pending VPC before deleting it via VPC → Internet gateways → Actions → Delete internet gateway.",
                        verify="Re-scan in AWS Clarity and confirm the detached Internet Gateway no longer appears.",
                        resource=r,
                    ))

            elif r_type == "nat_gateways":
                nat_id = r["id"]
                state = str(raw.get("state", "")).lower()
                if state == "failed":
                    issues.append(_issue(
                        rule_id="NAT-001",
                        severity="WARNING",
                        title="NAT Gateway is in a failed state",
                        why="A failed NAT Gateway cannot route outbound traffic for private subnets.",
                        evidence={"NatGateway": nat_id, "State": "failed"},
                        fix="Inspect subnet/EIP limits, recreate the NAT Gateway if needed, and update private route tables.",
                        verify="Confirm replacement NAT Gateway state is 'available' and re-scan in AWS Clarity.",
                        resource=r,
                    ))
                elif state == "available":
                    issues.append(_issue(
                        rule_id="NAT-002",
                        severity="INFO",
                        title="Active NAT Gateway (review ongoing hourly & data charges)",
                        why="NAT Gateways are often legitimately required for private subnet egress, but they incur continuous hourly and per-GB data-processing charges even with minimal traffic—making them a frequent source of unexpected AWS bills.",
                        evidence={"NatGateway": nat_id, "State": "available", "SubnetId": str(raw.get("subnet_id") or "unknown")},
                        fix="Review private subnet route tables before making changes—deleting an actively used NAT Gateway will break outbound internet access for private workloads. If workloads only need S3/DynamoDB, consider free VPC Gateway Endpoints; delete only if confirmed unused.",
                        verify="If you intentionally removed an unused NAT Gateway, re-scan in AWS Clarity to confirm it is no longer active.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # EBS Volumes & Snapshots (EBS)
            # ------------------------------------------------------------------
            elif r_type == "ebs_volumes":
                vol_state = str(raw.get("state", "")).lower()
                vol_size = raw.get("size")

                if raw.get("encrypted") is False:
                    issues.append(_issue(
                        rule_id="EBS-001",
                        severity="WARNING",
                        title="EBS volume is not encrypted at rest",
                        why="Unencrypted volumes expose block storage and snapshots if accessed outside intended controls.",
                        evidence={"Volume": r["id"], "SizeGB": str(vol_size) if vol_size is not None else "unknown", "Encrypted": "False"},
                        fix="Create a snapshot, copy it with KMS encryption enabled, restore an encrypted volume, and enable EBS encryption by default in EC2 settings.",
                        verify="Confirm the replacement volume shows Encrypted=true and re-scan in AWS Clarity.",
                        resource=r,
                    ))

                if vol_state == "available":
                    issues.append(_issue(
                        rule_id="EBS-002",
                        severity="UNUSED",
                        title="Unattached EBS volume incurring storage charges",
                        why="Unattached volumes continue billing monthly per provisioned GB even though no EC2 instance is currently using them.",
                        evidence={
                            "Volume": r["id"],
                            "State": "available (unattached)",
                            "SizeGB": str(vol_size) if vol_size is not None else "unknown",
                            "VolumeType": str(raw.get("volume_type") or "unknown"),
                        },
                        fix="Deleting an EBS volume permanently destroys its data. First check tags/ownership and create an EBS snapshot if data might be needed later, then delete the volume manually from EC2 → Volumes.",
                        verify="Re-scan in AWS Clarity and verify EBS-002 is cleared.",
                        resource=r,
                    ))

            elif r_type == "snapshots":
                vol_id = raw.get("volume_id")
                snap_region = r.get("region")
                if snap_region in failed_ebs_regions:
                    rule_errors["SNAP-001"] = "Could not verify source volume because EBS volume discovery failed in this region."
                elif vol_id and vol_id not in active_volume_ids:
                    issues.append(_issue(
                        rule_id="SNAP-001",
                        severity="INFO",
                        title="EBS snapshot whose original volume no longer exists (review before deleting)",
                        why="The original EBS volume for this snapshot no longer exists. This is NOT automatically wasteful or disposable—many snapshots are intentional backups, AMI backing snapshots, or compliance archives, though they continue incurring snapshot storage charges.",
                        evidence={"Snapshot": r["id"], "SourceVolumeId": vol_id, "VolumeSizeGB": str(raw.get("volume_size") or "unknown")},
                        fix="Before deleting, confirm this snapshot is not backing an active AMI, disaster-recovery backup, or compliance retention policy (deletion is permanent). Only if confirmed obsolete, delete manually in EC2 → Snapshots.",
                        verify="After reviewing or removing obsolete snapshots, re-scan in AWS Clarity to confirm your updated EBS snapshot inventory.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # RDS Instances
            # ------------------------------------------------------------------
            elif r_type == "rds_instances":
                engine = str(raw.get("engine") or "unknown")

                if raw.get("publicly_accessible") is True:
                    issues.append(_issue(
                        rule_id="RDS-001",
                        severity="CRITICAL",
                        title="RDS database is publicly accessible",
                        why="Publicly accessible databases receive a public IP and can be targeted directly from outside your VPC.",
                        evidence={"Database": r["id"], "Engine": engine, "PubliclyAccessible": "True"},
                        fix="Open RDS → Databases → Select DB → Modify → Connectivity → Additional configuration → set 'Not publicly accessible'.",
                        verify="Confirm Publicly accessible is 'No' in RDS Console, then re-scan in AWS Clarity to confirm RDS-001 resolves.",
                        resource=r,
                    ))

                if raw.get("storage_encrypted") is False:
                    issues.append(_issue(
                        rule_id="RDS-002",
                        severity="WARNING",
                        title="RDS database storage is not encrypted",
                        why="Unencrypted database storage and automated snapshots risk exposing sensitive records at rest.",
                        evidence={"Database": r["id"], "Engine": engine, "StorageEncrypted": "False"},
                        fix="Create a DB snapshot, copy it with encryption enabled, restore a new encrypted DB instance, and cut over traffic.",
                        verify="Confirm the new instance shows StorageEncrypted=true and re-scan in AWS Clarity.",
                        resource=r,
                    ))

                if raw.get("deletion_protection") is False:
                    issues.append(_issue(
                        rule_id="RDS-003",
                        severity="WARNING",
                        title="RDS deletion protection is disabled",
                        why="Without deletion protection, a single console click or API call can permanently destroy the database.",
                        evidence={"Database": r["id"], "Engine": engine, "DeletionProtection": "Disabled"},
                        fix="Open RDS → Databases → Select DB → Modify → Enable deletion protection → Apply immediately.",
                        verify="Re-scan in AWS Clarity and confirm RDS-003 passes.",
                        resource=r,
                    ))

                if raw.get("backup_retention_period") == 0:
                    issues.append(_issue(
                        rule_id="RDS-004",
                        severity="WARNING",
                        title="RDS automated backups are disabled",
                        why="A 0-day backup retention period disables automated snapshots and point-in-time recovery.",
                        evidence={"Database": r["id"], "Engine": engine, "BackupRetentionDays": "0"},
                        fix="Open RDS → Databases → Select DB → Modify → Backup → set Backup retention period to at least 7 days.",
                        verify="Confirm Backup retention period > 0 in RDS Console, then re-scan in AWS Clarity.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # DynamoDB Tables
            # ------------------------------------------------------------------
            elif r_type == "dynamodb_tables":
                table_name = r["name"]
                sse_desc = raw.get("sse_description") or {}
                if sse_desc.get("Status") == "DISABLED":
                    issues.append(_issue(
                        rule_id="DDB-001",
                        severity="WARNING",
                        title="DynamoDB table encryption at rest is disabled",
                        why="Table explicitly reports server-side encryption disabled.",
                        evidence={"Table": table_name, "SSEStatus": "DISABLED"},
                        fix="Enable encryption at rest in DynamoDB → Table → Additional settings → Encryption at rest.",
                        verify="Re-scan in AWS Clarity and confirm DDB-001 passes.",
                        resource=r,
                    ))

                if raw.get("billing_mode") == "PROVISIONED" and raw.get("item_count") == 0:
                    issues.append(_issue(
                        rule_id="DDB-002",
                        severity="INFO",
                        title="Empty provisioned DynamoDB table (review capacity mode)",
                        why="An empty provisioned table is NOT automatically wasteful—AWS updates ItemCount roughly every 6 hours, and up to 25 RCU/WCU falls under the Always-Free tier. Review whether On-Demand (PAY_PER_REQUEST) mode is a better fit if the table stays idle.",
                        evidence={
                            "Table": table_name,
                            "BillingMode": "PROVISIONED",
                            "ItemCount": "0",
                            "RCU": str(raw.get("read_capacity_units") or "unknown"),
                            "WCU": str(raw.get("write_capacity_units") or "unknown"),
                        },
                        fix="Verify the table is not actively receiving writes or reserved for an application. Prefer switching to On-Demand (PAY_PER_REQUEST) capacity mode rather than deleting; delete only after confirming no dependencies or backups are needed.",
                        verify="Re-scan in AWS Clarity and verify DDB-002 resolves.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # Lambda Functions
            # ------------------------------------------------------------------
            elif r_type == "lambda_functions":
                fn_name = r["name"]
                last_mod = raw.get("last_modified")
                dt = _parse_datetime(last_mod)
                if last_mod and dt is None:
                    rule_errors["LAM-001"] = "Could not parse Lambda LastModified timestamp."
                elif dt is not None:
                    age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
                    if age_days > 90:
                        issues.append(_issue(
                            rule_id="LAM-001",
                            severity="INFO",
                            title="Lambda function unchanged for over 90 days (informational review)",
                            why="A function that has not been edited in over 90 days is NOT automatically unhealthy or unused—many stable serverless functions run reliably for months without code changes. Periodic review helps ensure dependencies and IAM roles remain current.",
                            evidence={"Function": fn_name, "LastModified": str(last_mod), "DaysSinceModified": str(age_days)},
                            fix="Check CloudWatch invocation metrics and event triggers (API Gateway, EventBridge, S3, SQS) before making changes. Keep active functions intact (updating dependencies when needed), and delete only if confirmed unused and removed from IaC.",
                            verify="If you update dependencies/runtime or remove a confirmed obsolete function, re-scan in AWS Clarity to confirm the change.",
                            resource=r,
                        ))

                runtime = raw.get("runtime")
                if runtime and runtime in DEPRECATED_LAMBDA_RUNTIMES:
                    issues.append(_issue(
                        rule_id="LAM-002",
                        severity="WARNING",
                        title=f"Lambda function uses deprecated runtime ({runtime})",
                        why="End-of-life runtimes no longer receive security patches from AWS.",
                        evidence={"Function": fn_name, "Runtime": runtime},
                        fix="Upgrade the function to a currently supported AWS Lambda runtime (e.g. python3.12 or nodejs22.x) and redeploy.",
                        verify="Confirm the new runtime in Lambda → Function → Runtime settings, then re-scan in AWS Clarity.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # IAM Roles (Context-Aware)
            # ------------------------------------------------------------------
            elif r_type == "iam_roles":
                role_name = raw.get("role_name", r["name"])
                is_service_linked = bool(raw.get("is_service_linked"))

                # AWS service-linked roles (/aws-service-role/) are AWS-managed and immutable;
                # skip false-positive customer policy warnings on them.
                if not is_service_linked:
                    seen_wildcard_action = False
                    seen_broad_service_action = False
                    inline_policies = raw.get("inline_policies")

                    if isinstance(inline_policies, dict):
                        for policy_name, policy_document in inline_policies.items():
                            statements = policy_document.get("Statement", [])
                            if isinstance(statements, dict):
                                statements = [statements]

                            for stmt in statements:
                                if stmt.get("Effect") != "Allow":
                                    continue
                                has_condition = _has_strong_condition(stmt)

                                actions = stmt.get("Action", [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                not_actions = stmt.get("NotAction", [])
                                if isinstance(not_actions, str):
                                    not_actions = [not_actions]

                                resources_list = stmt.get("Resource", [])
                                if isinstance(resources_list, str):
                                    resources_list = [resources_list]
                                has_star_resource = "*" in resources_list

                                # IAM-001: Action: *, iam:*, or Allow+NotAction on Resource: * without strong condition
                                is_admin_wildcard = (
                                    "*" in actions
                                    or "iam:*" in actions
                                    or (bool(not_actions) and has_star_resource)
                                )
                                if is_admin_wildcard and has_star_resource and not has_condition and not seen_wildcard_action:
                                    seen_wildcard_action = True
                                    issues.append(_issue(
                                        rule_id="IAM-001",
                                        severity="CRITICAL",
                                        title="IAM role has unrestricted admin wildcard permissions",
                                        why="Granting Action: *, iam:*, or Allow+NotAction on Resource: * without conditions enables full account takeover or privilege escalation.",
                                        evidence={
                                            "Role": role_name,
                                            "Policy": policy_name,
                                            "Action": "*" if "*" in actions else ("iam:*" if "iam:*" in actions else f"NotAction:{not_actions[0]}"),
                                            "Resource": ", ".join(resources_list[:5]),
                                            "Condition": "None",
                                        },
                                        fix="Replace the wildcard statement in IAM → Roles → Permissions with explicit least-privilege actions, specific ARNs, and scoping conditions.",
                                        verify="Re-scan in AWS Clarity after updating the inline policy to confirm IAM-001 is resolved.",
                                        resource=r,
                                    ))

                                # IAM-006: Broad service wildcard (e.g. s3:*, ec2:*) on Resource: * without strong condition
                                broad_service_actions = [
                                    a for a in actions if a.endswith(":*") and a not in ("iam:*", "*")
                                ]
                                if (
                                    broad_service_actions
                                    and has_star_resource
                                    and not has_condition
                                    and not seen_wildcard_action
                                    and not seen_broad_service_action
                                ):
                                    seen_broad_service_action = True
                                    issues.append(_issue(
                                        rule_id="IAM-006",
                                        severity="WARNING",
                                        title="IAM role grants unscoped service-wide wildcard actions",
                                        why="Service wildcards (e.g. s3:*, ec2:*) on Resource: * without conditions grant all read, write, and delete operations across that service.",
                                        evidence={
                                            "Role": role_name,
                                            "Policy": policy_name,
                                            "Actions": ", ".join(broad_service_actions[:5]),
                                            "Resource": "*",
                                            "Condition": "None",
                                        },
                                        fix="Replace service wildcards with only the specific API actions required and restrict Resource to target ARNs.",
                                        verify="Re-scan in AWS Clarity and confirm IAM-006 passes.",
                                        resource=r,
                                    ))

                                # IAM-002: Context-aware — only flag WRITE/DESTRUCTIVE actions on Resource: * without conditions.
                                # Read-only Describe*/List*/Get* actions legitimately require Resource: "*" in AWS.
                                write_actions = [
                                    a
                                    for a in actions
                                    if ":" in a
                                    and not a.endswith(":*")
                                    and a != "*"
                                    and not _is_read_only_action(a)
                                ]
                                if write_actions and has_star_resource and not has_condition:
                                    issues.append(_issue(
                                        rule_id="IAM-002",
                                        severity="WARNING",
                                        title="IAM role grants write actions across all resources (*)",
                                        why="Applying write or state-changing actions to Resource: * without conditions lets this role modify or delete every matching resource in the account.",
                                        evidence={
                                            "Role": role_name,
                                            "Policy": policy_name,
                                            "WriteActions": ", ".join(write_actions[:8]),
                                            "Resource": "*",
                                            "Condition": "None",
                                        },
                                        fix="Scope Resource to the exact ARNs this role needs to modify, or add an explicit Condition block (e.g. aws:ResourceTag).",
                                        verify="Re-scan in AWS Clarity after narrowing Resource ARNs and confirm IAM-002 resolves.",
                                        resource=r,
                                    ))

                    # Attached managed policies
                    attached_policies = raw.get("attached_managed_policies")
                    if isinstance(attached_policies, list):
                        dangerous_managed = {
                            "arn:aws:iam::aws:policy/AdministratorAccess": (
                                "IAM-003",
                                "CRITICAL",
                                "IAM role has AdministratorAccess attached",
                                "AdministratorAccess grants unrestricted control over every service and resource in your AWS account.",
                                "Detach AdministratorAccess in IAM → Roles → Permissions and attach a scoped least-privilege policy.",
                                "Confirm AdministratorAccess is detached in IAM Console, then re-scan in AWS Clarity.",
                            ),
                            "arn:aws:iam::aws:policy/IAMFullAccess": (
                                "IAM-004",
                                "WARNING",
                                "IAM role has IAMFullAccess attached",
                                "IAMFullAccess lets this role create or escalate any IAM role, user, or policy to full administrator.",
                                "Detach IAMFullAccess and grant only the specific IAM permissions required.",
                                "Re-scan in AWS Clarity after detaching IAMFullAccess to verify IAM-004 resolves.",
                            ),
                            "arn:aws:iam::aws:policy/PowerUserAccess": (
                                "IAM-007",
                                "WARNING",
                                "IAM role has PowerUserAccess attached",
                                "PowerUserAccess grants full read/write/delete rights across almost every AWS service.",
                                "Replace PowerUserAccess with a tailored policy listing only required service actions.",
                                "Re-scan in AWS Clarity and confirm IAM-007 passes.",
                            ),
                        }
                        for pol in attached_policies:
                            pol_arn = pol.get("PolicyArn", "")
                            pol_name = pol.get("PolicyName", pol_arn)
                            if pol_arn in dangerous_managed:
                                rule_id, sev, title, why, fix_text, verify_text = dangerous_managed[pol_arn]
                                issues.append(_issue(
                                    rule_id=rule_id,
                                    severity=sev,
                                    title=title,
                                    why=why,
                                    evidence={"Role": role_name, "PolicyName": pol_name, "PolicyArn": pol_arn},
                                    fix=fix_text,
                                    verify=verify_text,
                                    resource=r,
                                ))

                    # Trust relationship checks (context-aware with Conditions & current account_id)
                    trust_doc = raw.get("trust_policy") or {}
                    trust_statements = trust_doc.get("Statement", [])
                    if isinstance(trust_statements, dict):
                        trust_statements = [trust_statements]

                    role_own_account = account_id or _extract_account_from_principal(raw.get("arn", ""))

                    for stmt in trust_statements:
                        if stmt.get("Effect") != "Allow":
                            continue
                        principal = stmt.get("Principal", {})
                        has_trust_condition = _has_strong_condition(stmt)
                        is_public = (
                            principal == "*"
                            or (isinstance(principal, dict) and principal.get("AWS") == "*")
                            or (isinstance(principal, dict) and principal.get("Service") == "*")
                        )
                        if is_public and not has_trust_condition:
                            issues.append(_issue(
                                rule_id="IAM-005",
                                severity="CRITICAL",
                                title="IAM role trust policy allows anyone (*)",
                                why="A trust policy with Principal: * and no scoping condition allows any external AWS account to assume this role.",
                                evidence={"Role": role_name, "Principal": "*", "Condition": "None"},
                                fix="Edit IAM → Roles → Trust relationships and replace Principal: '*' with the exact AWS account ID, role ARN, or service principal.",
                                verify="Confirm Principal: '*' is removed in Trust relationships, then re-scan in AWS Clarity.",
                                resource=r,
                            ))
                            break

                        if isinstance(principal, dict) and "AWS" in principal:
                            aws_p = principal["AWS"]
                            aws_principals = aws_p if isinstance(aws_p, list) else [aws_p]
                            condition = stmt.get("Condition") or {}
                            has_ext_or_org = any(
                                any(
                                    str(ck).lower() in ("sts:externalid", "aws:principalorgid")
                                    for ck in cv.keys()
                                )
                                for cv in condition.values()
                                if isinstance(cv, dict)
                            )
                            for p_arn in aws_principals:
                                trusted_account = _extract_account_from_principal(p_arn)
                                if not trusted_account:
                                    continue
                                if role_own_account and trusted_account == role_own_account:
                                    continue
                                if not has_ext_or_org:
                                    issues.append(_issue(
                                        rule_id="IAM-008",
                                        severity="WARNING",
                                        title="Cross-account trust missing ExternalId or Org condition",
                                        why="Allowing an external AWS account to assume this role without sts:ExternalId or aws:PrincipalOrgID exposes it to confused deputy attacks.",
                                        evidence={"Role": role_name, "TrustedPrincipal": p_arn, "MissingCondition": "sts:ExternalId / aws:PrincipalOrgID"},
                                        fix="Add a StringEquals Condition requiring 'sts:ExternalId' (for third-party accounts) or 'aws:PrincipalOrgID' (for accounts in your own AWS Organization) to the role's trust policy. If both accounts are strictly internal without AWS Organizations, review and document the trust intentionally.",
                                        verify="Re-scan in AWS Clarity after updating the trust policy to confirm IAM-008 passes.",
                                        resource=r,
                                    ))
                                    break

            # ------------------------------------------------------------------
            # IAM Users
            # ------------------------------------------------------------------
            elif r_type == "iam_users":
                user_name = raw.get("user_name", r["name"])
                mfa_count = raw.get("mfa_devices_count")
                attached = raw.get("attached_managed_policies") or []
                inline = raw.get("inline_policies") or {}

                has_admin_policy = any(
                    p.get("PolicyArn") == "arn:aws:iam::aws:policy/AdministratorAccess"
                    for p in attached
                )
                has_admin_inline = False
                if isinstance(inline, dict):
                    for doc in inline.values():
                        stmts = doc.get("Statement", [])
                        if isinstance(stmts, dict):
                            stmts = [stmts]
                        for stmt in stmts:
                            acts = stmt.get("Action", [])
                            if isinstance(acts, str):
                                acts = [acts]
                            res_list = stmt.get("Resource", [])
                            if isinstance(res_list, str):
                                res_list = [res_list]
                            if stmt.get("Effect") == "Allow" and "*" in acts and "*" in res_list:
                                has_admin_inline = True

                # IAM-009: Console user or admin user without MFA
                if mfa_count == 0 and (raw.get("password_last_used") is not None or has_admin_policy or has_admin_inline):
                    issues.append(_issue(
                        rule_id="IAM-009",
                        severity="CRITICAL",
                        title="IAM user does not have MFA enabled",
                        why="Without Multi-Factor Authentication, a single leaked password or credential grants immediate access to your AWS account.",
                        evidence={
                            "User": user_name,
                            "MFADevices": "0",
                            "ConsoleActivity": str(raw.get("password_last_used") or "Admin privileges"),
                        },
                        fix="Open IAM → Users → Select User → Security credentials → Assign MFA device (hardware key or authenticator app).",
                        verify="Confirm at least one MFA device is active for this user, then re-scan in AWS Clarity.",
                        resource=r,
                    ))

                # IAM-010: Active access key older than 90 days
                access_keys = raw.get("access_keys")
                if isinstance(access_keys, list):
                    stale_keys = []
                    now = datetime.datetime.now(datetime.timezone.utc)
                    for k in access_keys:
                        if k.get("status") != "Active":
                            continue
                        created = _parse_datetime(k.get("create_date"))
                        if created is not None and (now - created).days > 90:
                            stale_keys.append(f"{k.get('access_key_id')} ({(now - created).days}d)")
                    if stale_keys:
                        issues.append(_issue(
                            rule_id="IAM-010",
                            severity="WARNING",
                            title="Long-lived active IAM access key (>90 days)",
                            why="Key age alone does not mean a key is compromised, but long-lived static credentials carry a larger blast radius if ever leaked. Rotating keys or migrating to temporary IAM roles reduces exposure.",
                            evidence={"User": user_name, "KeysOver90Days": ", ".join(stale_keys)},
                            fix="Do NOT delete an active key immediately—doing so can break scripts or CI pipelines. Create a replacement key (or migrate the workload to an IAM role), update all dependent applications, deactivate the old key first to confirm nothing breaks, and then delete it.",
                            verify="Re-scan in AWS Clarity after replacing and removing active keys older than 90 days.",
                            resource=r,
                        ))

                # IAM-011: Direct AdministratorAccess or Action:* on user
                if has_admin_policy or has_admin_inline:
                    issues.append(_issue(
                        rule_id="IAM-011",
                        severity="CRITICAL",
                        title="IAM user has direct full administrator permissions",
                        why="Attaching AdministratorAccess or Action: * directly to an IAM user violates least privilege and complicates access governance.",
                        evidence={
                            "User": user_name,
                            "DirectAdminPolicy": "AdministratorAccess" if has_admin_policy else "Inline Action:*",
                        },
                        fix="Manage permissions via IAM groups or temporary assumable IAM roles (or AWS IAM Identity Center) rather than attaching admin rights directly to users.",
                        verify="Detach direct admin policies from the user and re-scan in AWS Clarity to confirm IAM-011 resolves.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # CloudWatch Alarms & Log Groups (CloudWatch)
            # ------------------------------------------------------------------
            elif r_type == "cloudwatch_alarms":
                alarm_name = r["name"]
                if raw.get("actions_enabled") is False:
                    issues.append(_issue(
                        rule_id="CW-001",
                        severity="WARNING",
                        title="CloudWatch alarm actions are disabled",
                        why="When alarm actions are disabled, alerts will not notify operators or trigger remediation when thresholds breach.",
                        evidence={"Alarm": alarm_name, "ActionsEnabled": "False"},
                        fix="Open CloudWatch → Alarms → Select Alarm → Actions → Enable actions (or delete the alarm if obsolete).",
                        verify="Re-scan in AWS Clarity and confirm CW-001 passes.",
                        resource=r,
                    ))
                if raw.get("state_value") == "INSUFFICIENT_DATA":
                    issues.append(_issue(
                        rule_id="CW-002",
                        severity="INFO",
                        title="CloudWatch alarm currently in INSUFFICIENT_DATA state (review metric)",
                        why="INSUFFICIENT_DATA is NOT automatically a failure—it is common for sparse/event-driven metrics, newly created alarms, or alarms waiting for a metric period. Review to confirm whether the monitored resource still exists and missing-data treatment is intentional.",
                        evidence={"Alarm": alarm_name, "StateValue": "INSUFFICIENT_DATA"},
                        fix="Open CloudWatch → Alarms → Select Alarm and inspect the metric dimensions and 'Missing data treatment' setting. Keep alarms monitoring sparse workloads; update dimensions or delete only if the monitored resource was permanently removed.",
                        verify="If you adjust the alarm configuration or remove a confirmed orphaned alarm, re-scan in AWS Clarity to confirm.",
                        resource=r,
                    ))

            elif r_type == "cloudwatch_log_groups":
                lg_name = r["name"]
                if raw.get("retention_in_days") is None:
                    stored_mb = round((raw.get("stored_bytes") or 0) / (1024 * 1024), 2)
                    issues.append(_issue(
                        rule_id="CW-003",
                        severity="WARNING",
                        title="CloudWatch Log Group has no retention policy (Never Expire)",
                        why="Log groups without a retention policy store logs forever, causing CloudWatch storage charges to grow steadily over time.",
                        evidence={"LogGroup": lg_name, "Retention": "Never Expire", "StoredMB": f"{stored_mb} MB"},
                        fix="Open CloudWatch → Log groups → Select Log Group → Actions → Edit retention setting (e.g. 14, 30, or 90 days).",
                        verify="Confirm a retention period is shown on the log group, then re-scan in AWS Clarity.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # CloudTrail Trails (CloudTrail)
            # ------------------------------------------------------------------
            elif r_type == "cloudtrail_trails":
                trail_name = r["name"]
                if raw.get("is_logging") is False:
                    issues.append(_issue(
                        rule_id="CT-001",
                        severity="CRITICAL",
                        title="CloudTrail trail logging is turned off",
                        why="With logging stopped, AWS API activity is not being recorded for security investigations or incident response.",
                        evidence={"Trail": trail_name, "IsLogging": "False", "HomeRegion": str(raw.get("home_region"))},
                        fix="Open CloudTrail → Trails → Select Trail → click 'Start logging'.",
                        verify="Confirm Trail status shows 'Logging' in CloudTrail Console, then re-scan in AWS Clarity.",
                        resource=r,
                    ))
                if raw.get("is_multi_region_trail") is False:
                    issues.append(_issue(
                        rule_id="CT-002",
                        severity="WARNING",
                        title="CloudTrail trail is single-region only",
                        why="A single-region trail misses unauthorized API activity or resource creation in other enabled AWS regions.",
                        evidence={"Trail": trail_name, "IsMultiRegionTrail": "False", "HomeRegion": str(raw.get("home_region"))},
                        fix="Open CloudTrail → Trails → Select Trail → Edit → enable 'Multi-region trail'.",
                        verify="Re-scan in AWS Clarity and confirm CT-002 resolves.",
                        resource=r,
                    ))
                if raw.get("log_file_validation_enabled") is False:
                    issues.append(_issue(
                        rule_id="CT-003",
                        severity="WARNING",
                        title="CloudTrail log file integrity validation is disabled",
                        why="Without log file validation, you cannot cryptographically detect if audit logs were modified or deleted after delivery.",
                        evidence={"Trail": trail_name, "LogFileValidationEnabled": "False"},
                        fix="Open CloudTrail → Trails → Select Trail → Edit → Additional settings → enable 'Log file validation'.",
                        verify="Re-scan in AWS Clarity and confirm CT-003 passes.",
                        resource=r,
                    ))

            # ------------------------------------------------------------------
            # Filter, deduplicate, compute explicit assessment & resource status
            # ------------------------------------------------------------------
            issues = [
                issue
                for issue in issues
                if issue.get("rule_id") not in rule_errors
                and _has_rule_evidence(raw, issue.get("rule_id"))
            ]
            seen_rule_ids = set()
            unique_issues = []
            for issue in issues:
                if issue["rule_id"] not in seen_rule_ids:
                    seen_rule_ids.add(issue["rule_id"])
                    unique_issues.append(issue)

            r["issues"] = unique_issues
            assessment = _assessment(rule_ids, raw, unique_issues, rule_errors)
            r["assessment"] = assessment

            has_crit = any(i["severity"] == "CRITICAL" for i in unique_issues)
            has_warn = any(i["severity"] == "WARNING" for i in unique_issues)
            has_unused = any(i["severity"] == "UNUSED" for i in unique_issues)

            if has_crit:
                r["status"] = "CRITICAL"
            elif has_warn:
                r["status"] = "WARNING"
            elif has_unused:
                r["status"] = "UNUSED"
            elif assessment["status"] == "COMPLETE":
                # Resource is HEALTHY when EVERY applicable implemented check ran cleanly
                # and no CRITICAL/WARNING/UNUSED findings triggered (INFO observations remain inspectable
                # without falsely branding the resource unhealthy).
                r["status"] = "HEALTHY"
            else:
                r["status"] = "INCOMPLETE"

    return resources
