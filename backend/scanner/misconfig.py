import datetime
import re
from botocore.exceptions import ClientError

# Database ports commonly targeted when accidentally exposed to the public internet.
SENSITIVE_DB_PORTS = {
    1433: "MSSQL",
    3306: "MySQL/Aurora",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

# AWS Lambda runtimes that have reached End of Support / Deprecation.
DEPRECATED_LAMBDA_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x",
    "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet6",
    "ruby2.5", "ruby2.7", "ruby3.2",
    "java8", "go1.x", "provided",
}

# Authoritative metadata for every rule implemented by AWS Clarity.
# This single registry drives finding enrichment and the frontend Security Checks Catalog.
RULE_METADATA = {
    # ── Security Groups ──────────────────────────────────────────────────────
    "SG-001": {
        "name": "Unrestricted Inbound Traffic (All Ports)",
        "service": "EC2",
        "resource_type": "security_group",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether inbound firewall rules allow all protocols and all ports from 0.0.0.0/0 or ::/0.",
        "what_found": "Inbound firewall rule allows all protocols (-1) and all ports from 0.0.0.0/0 or ::/0.",
        "what_checked": "Evaluated Security Group ingress IP permissions for unrestricted CIDR routes across all protocols.",
    },
    "SG-002": {
        "name": "Unrestricted SSH Access (Port 22)",
        "service": "EC2",
        "resource_type": "security_group",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether inbound SSH (port 22) is exposed to the public internet (0.0.0.0/0 or ::/0).",
        "what_found": "Inbound SSH access is allowed from 0.0.0.0/0 or ::/0 on port 22.",
        "what_checked": "Evaluated Security Group ingress IP permissions for port 22 with unrestricted CIDR sources.",
    },
    "SG-003": {
        "name": "Unrestricted RDP Access (Port 3389)",
        "service": "EC2",
        "resource_type": "security_group",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether inbound Windows RDP (port 3389) is exposed to the public internet (0.0.0.0/0 or ::/0).",
        "what_found": "Inbound RDP access is allowed from 0.0.0.0/0 or ::/0 on port 3389.",
        "what_checked": "Evaluated Security Group ingress IP permissions for port 3389 with unrestricted CIDR sources.",
    },
    "SG-004": {
        "name": "Database Port Exposed to Internet",
        "service": "EC2",
        "resource_type": "security_group",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether common database ports (MySQL 3306, PostgreSQL 5432, MSSQL 1433, Redis 6379, MongoDB 27017) are open to 0.0.0.0/0 or ::/0.",
        "what_found": "Inbound firewall rule exposes a database port directly to the public internet.",
        "what_checked": "Evaluated Security Group ingress port ranges against common database ports with unrestricted CIDR sources.",
    },

    # ── S3 Buckets ───────────────────────────────────────────────────────────
    "S3-001": {
        "name": "Empty S3 Bucket",
        "service": "S3",
        "resource_type": "s3_bucket",
        "severity": "ORPHANED",
        "category": "Unused",
        "what_it_checks": "Checks whether an S3 bucket contains zero objects and may be leftover clutter.",
        "what_found": "Bucket contains 0 objects and has no active storage usage.",
        "what_checked": "Queried S3 ListObjectsV2 (MaxKeys=1) to check whether the bucket holds any objects.",
    },
    "S3-002": {
        "name": "Public Access via Bucket Policy",
        "service": "S3",
        "resource_type": "s3_bucket",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether an S3 bucket policy permits public read or write access from the internet.",
        "what_found": "Bucket policy explicitly allows public read or write access from the internet.",
        "what_checked": "Queried S3 GetBucketPolicyStatus API to evaluate policy public access.",
    },
    "S3-003": {
        "name": "Public Access via Bucket ACL",
        "service": "S3",
        "resource_type": "s3_bucket",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether an S3 bucket Access Control List (ACL) grants public access to AllUsers or AuthenticatedUsers.",
        "what_found": "Bucket Access Control List (ACL) grants permissions to AllUsers or AuthenticatedUsers.",
        "what_checked": "Queried S3 GetBucketAcl API and inspected grantee URI definitions.",
    },
    "S3-004": {
        "name": "Server-Side Encryption Configuration",
        "service": "S3",
        "resource_type": "s3_bucket",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Verifies S3 default server-side encryption configuration is readable and active (accounting for AWS default SSE-S3).",
        "what_found": "Inspected explicit bucket encryption configuration; AWS S3 applies SSE-S3 by default to new uploads.",
        "what_checked": "Queried S3 GetBucketEncryption and accounted for AWS S3 default SSE-S3 encryption.",
    },
    "S3-005": {
        "name": "Incomplete Block Public Access",
        "service": "S3",
        "resource_type": "s3_bucket",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether all 4 S3 Block Public Access settings are enabled to prevent accidental exposure.",
        "what_found": "One or more of the four S3 Block Public Access controls are disabled.",
        "what_checked": "Queried S3 GetPublicAccessBlock configuration for all 4 security flags.",
    },

    # ── EC2 Instances ────────────────────────────────────────────────────────
    "EC2-001": {
        "name": "Stopped EC2 Instance",
        "service": "EC2",
        "resource_type": "ec2_instance",
        "severity": "ORPHANED",
        "category": "Cost Risk",
        "what_it_checks": "Checks whether an EC2 instance is stopped while retaining attached EBS storage and Elastic IPs that continue generating charges.",
        "what_found": "EC2 instance is in 'stopped' state while retaining attached storage and IPs.",
        "what_checked": "Inspected EC2 DescribeInstances instance state.",
    },
    "EC2-002": {
        "name": "IMDSv2 Not Enforced",
        "service": "EC2",
        "resource_type": "ec2_instance",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether an active EC2 instance requires Instance Metadata Service v2 (HttpTokens=required) to protect IAM credentials against SSRF.",
        "what_found": "EC2 instance still permits IMDSv1 (HttpTokens is not set to 'required').",
        "what_checked": "Inspected EC2 DescribeInstances MetadataOptions.HttpTokens attribute.",
    },

    # ── EBS Volumes & Snapshots ──────────────────────────────────────────────
    "EBS-001": {
        "name": "EBS Volume Unencrypted",
        "service": "EC2",
        "resource_type": "ebs_volume",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether an EBS block storage volume is encrypted at rest.",
        "what_found": "EBS volume block storage has encryption disabled.",
        "what_checked": "Inspected EC2 DescribeVolumes Encrypted attribute.",
    },
    "EBS-002": {
        "name": "Unattached EBS Volume",
        "service": "EC2",
        "resource_type": "ebs_volume",
        "severity": "ORPHANED",
        "category": "Cost Risk",
        "what_it_checks": "Checks whether an EBS volume is in 'available' state (not attached to any EC2 instance) and incurring ongoing storage charges.",
        "what_found": "EBS volume is in 'available' state and not attached to any EC2 instance.",
        "what_checked": "Inspected EC2 DescribeVolumes State and Attachments list.",
    },
    "SNAP-001": {
        "name": "Orphaned EBS Snapshot",
        "service": "EC2",
        "resource_type": "ebs_snapshot",
        "severity": "ORPHANED",
        "category": "Cost Risk",
        "what_it_checks": "Checks whether an EBS snapshot's source volume has been deleted while the snapshot continues incurring storage charges.",
        "what_found": "The EBS volume from which this snapshot was taken has been deleted or cannot be found.",
        "what_checked": "Cross-referenced Snapshot VolumeId against active EBS volumes in the region.",
    },

    # ── Elastic IPs ──────────────────────────────────────────────────────────
    "EIP-001": {
        "name": "Unassociated Elastic IP",
        "service": "EC2",
        "resource_type": "elastic_ip",
        "severity": "ORPHANED",
        "category": "Cost Risk",
        "what_it_checks": "Checks whether an Elastic IP address is unattached to any instance or network interface, incurring hourly IPv4 charges.",
        "what_found": "Elastic IP address has no active AssociationId or attached network interface.",
        "what_checked": "Inspected EC2 DescribeAddresses AssociationId field.",
    },

    # ── RDS Databases ────────────────────────────────────────────────────────
    "RDS-001": {
        "name": "Publicly Accessible Database",
        "service": "RDS",
        "resource_type": "rds_instance",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether an RDS instance has PubliclyAccessible enabled instead of being restricted to private subnets.",
        "what_found": "RDS instance PubliclyAccessible flag is set to true.",
        "what_checked": "Inspected RDS DescribeDBInstances PubliclyAccessible configuration.",
    },
    "RDS-002": {
        "name": "Database Storage Unencrypted",
        "service": "RDS",
        "resource_type": "rds_instance",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether an RDS database storage volume is encrypted at rest.",
        "what_found": "RDS instance storage encryption is disabled.",
        "what_checked": "Inspected RDS DescribeDBInstances StorageEncrypted attribute.",
    },
    "RDS-003": {
        "name": "Database Deletion Protection Disabled",
        "service": "RDS",
        "resource_type": "rds_instance",
        "severity": "WARNING",
        "category": "Reliability",
        "what_it_checks": "Checks whether accidental deletion protection is enabled on RDS databases.",
        "what_found": "Deletion protection is disabled on this RDS instance.",
        "what_checked": "Inspected RDS DescribeDBInstances DeletionProtection attribute.",
    },
    "RDS-004": {
        "name": "Automated Backups Disabled",
        "service": "RDS",
        "resource_type": "rds_instance",
        "severity": "WARNING",
        "category": "Reliability",
        "what_it_checks": "Checks whether an RDS instance has automated backups disabled (BackupRetentionPeriod = 0).",
        "what_found": "RDS automated backup retention period is set to 0 days.",
        "what_checked": "Inspected RDS DescribeDBInstances BackupRetentionPeriod attribute.",
    },

    # ── DynamoDB Tables ──────────────────────────────────────────────────────
    "DDB-001": {
        "name": "DynamoDB Encryption Disabled",
        "service": "DynamoDB",
        "resource_type": "dynamodb_table",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether a DynamoDB table reports encryption at rest explicitly disabled.",
        "what_found": "DynamoDB table encryption at rest is explicitly disabled.",
        "what_checked": "Inspected DynamoDB DescribeTable SSEDescription configuration.",
    },
    "DDB-002": {
        "name": "Empty Provisioned DynamoDB Table",
        "service": "DynamoDB",
        "resource_type": "dynamodb_table",
        "severity": "ORPHANED",
        "category": "Cost Risk",
        "what_it_checks": "Checks whether a provisioned-capacity DynamoDB table contains 0 items and may be incurring unnecessary capacity charges.",
        "what_found": "DynamoDB table uses PROVISIONED billing mode while containing 0 items.",
        "what_checked": "Inspected DynamoDB DescribeTable BillingModeSummary and ItemCount.",
    },

    # ── IAM Roles ────────────────────────────────────────────────────────────
    "IAM-001": {
        "name": "Unrestricted Wildcard Action (*)",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether an inline IAM policy statement allows full administrative wildcard action (Action: * or iam:*).",
        "what_found": "Inline IAM policy statement contains Action: * or Action: iam:* with Effect: Allow.",
        "what_checked": "Parsed IAM role inline policy documents for unrestricted Action: * statements.",
    },
    "IAM-002": {
        "name": "Unrestricted Resource Scope (*)",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether inline IAM policy actions apply to all account resources (Resource: *) without ARN restriction.",
        "what_found": "IAM policy statements grant actions with Resource: * without resource scoping.",
        "what_checked": "Parsed IAM role inline policy documents for statements with Resource: *.",
    },
    "IAM-003": {
        "name": "AdministratorAccess Managed Policy",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether the AWS-managed AdministratorAccess policy is attached to an IAM role.",
        "what_found": "AWS managed policy AdministratorAccess is attached to this IAM role.",
        "what_checked": "Inspected IAM ListAttachedRolePolicies for AdministratorAccess.",
    },
    "IAM-004": {
        "name": "IAMFullAccess Managed Policy",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether the IAMFullAccess managed policy is attached, enabling potential privilege escalation.",
        "what_found": "AWS managed policy IAMFullAccess is attached to this IAM role.",
        "what_checked": "Inspected IAM ListAttachedRolePolicies for IAMFullAccess.",
    },
    "IAM-005": {
        "name": "Public Role Trust Relationship",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "CRITICAL",
        "category": "Security",
        "what_it_checks": "Checks whether an IAM role trust policy allows anyone (Principal: *) to assume the role.",
        "what_found": "Role trust policy allows Principal: * or AWS: * to assume the role.",
        "what_checked": "Parsed AssumeRolePolicyDocument for wildcard Principal definitions.",
    },
    "IAM-006": {
        "name": "Broad Service-Level Wildcard Actions",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether inline policy statements grant service-wide wildcards (e.g. s3:*, ec2:*) combined with Resource: *.",
        "what_found": "IAM policy statement grants full wildcard actions across an entire service (e.g. s3:*, ec2:*).",
        "what_checked": "Parsed IAM policy statements for actions ending with :* combined with Resource: *.",
    },
    "IAM-007": {
        "name": "PowerUserAccess Managed Policy",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether the broad PowerUserAccess managed policy is attached to an IAM role.",
        "what_found": "AWS managed policy PowerUserAccess is attached to this IAM role.",
        "what_checked": "Inspected IAM ListAttachedRolePolicies for PowerUserAccess.",
    },
    "IAM-008": {
        "name": "Cross-Account Trust Missing ExternalId",
        "service": "IAM",
        "resource_type": "iam_role",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether cross-account trust policies enforce an sts:ExternalId condition against confused deputy attacks.",
        "what_found": "Cross-account trust relationship does not enforce an sts:ExternalId condition.",
        "what_checked": "Inspected AssumeRolePolicyDocument external AWS account principals for sts:ExternalId conditions.",
    },

    # ── Lambda Functions ─────────────────────────────────────────────────────
    "LAM-001": {
        "name": "Stale Lambda Function (>90 Days)",
        "service": "Lambda",
        "resource_type": "lambda_function",
        "severity": "WARNING",
        "category": "Hygiene",
        "what_it_checks": "Checks whether a Lambda function has not been updated in over 90 days and may be unmaintained or obsolete.",
        "what_found": "Function code and configuration have not been updated in over 90 days.",
        "what_checked": "Inspected Lambda ListFunctions LastModified timestamp.",
    },
    "LAM-002": {
        "name": "Deprecated Lambda Runtime",
        "service": "Lambda",
        "resource_type": "lambda_function",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether a Lambda function uses a deprecated runtime that no longer receives AWS security patches.",
        "what_found": "Lambda function is configured with an end-of-life or deprecated runtime.",
        "what_checked": "Inspected Lambda ListFunctions Runtime attribute against deprecated runtimes.",
    },

    # ── VPC & Networking ─────────────────────────────────────────────────────
    "VPC-001": {
        "name": "Default VPC Present",
        "service": "VPC",
        "resource_type": "vpc",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether the AWS default VPC is active, as it uses public subnets and permissive default networking.",
        "what_found": "This VPC is the AWS default VPC with standard public subnets and open routing.",
        "what_checked": "Inspected EC2 DescribeVpcs IsDefault flag.",
    },
    "IGW-001": {
        "name": "Unattached Internet Gateway",
        "service": "VPC",
        "resource_type": "internet_gateway",
        "severity": "ORPHANED",
        "category": "Unused",
        "what_it_checks": "Checks whether an Internet Gateway exists without being attached to any VPC.",
        "what_found": "Internet Gateway exists but has no active VPC attachments.",
        "what_checked": "Inspected EC2 DescribeInternetGateways Attachments array.",
    },
    "NAT-001": {
        "name": "Failed NAT Gateway",
        "service": "VPC",
        "resource_type": "nat_gateway",
        "severity": "WARNING",
        "category": "Reliability",
        "what_it_checks": "Checks whether a NAT Gateway is in a failed state and unable to route private subnet traffic.",
        "what_found": "NAT Gateway is in a failed state and cannot route outbound internet traffic.",
        "what_checked": "Inspected EC2 DescribeNatGateways State attribute.",
    },
    "NAT-002": {
        "name": "Active NAT Gateway (Ongoing Charge Risk)",
        "service": "VPC",
        "resource_type": "nat_gateway",
        "severity": "WARNING",
        "category": "Cost Risk",
        "what_it_checks": "Flags active NAT Gateways because they incur continuous hourly and per-GB data processing charges — a common cause of unexpected AWS bills.",
        "what_found": "An active NAT Gateway incurs continuous hourly availability and data-processing charges.",
        "what_checked": "Inspected EC2 DescribeNatGateways State and SubnetId.",
    },

    # ── Elastic Load Balancing ───────────────────────────────────────────────
    "ELB-001": {
        "name": "Internet-Facing Load Balancer",
        "service": "ELB",
        "resource_type": "load_balancer",
        "severity": "WARNING",
        "category": "Security",
        "what_it_checks": "Checks whether a load balancer is internet-facing with a public DNS endpoint so you can confirm public exposure is intentional.",
        "what_found": "Load balancer scheme is configured as internet-facing with a public DNS name.",
        "what_checked": "Inspected Elastic Load Balancing DescribeLoadBalancers Scheme attribute.",
    },
    "ELB-002": {
        "name": "Legacy Classic Load Balancer",
        "service": "ELB",
        "resource_type": "load_balancer",
        "severity": "WARNING",
        "category": "Cost Risk",
        "what_it_checks": "Checks whether a legacy Classic Load Balancer (ELBv1) is running, which incurs hourly charges and lacks modern ALB/NLB capabilities.",
        "what_found": "Load balancer is a legacy Classic Load Balancer (ELBv1).",
        "what_checked": "Inspected Elastic Load Balancing load balancer type.",
    },
}

# Explicit mapping of supported resource collection keys → applicable rule IDs.
CHECKS_BY_RESOURCE = {
    "s3_buckets": ["S3-001", "S3-002", "S3-003", "S3-004", "S3-005"],
    "security_groups": ["SG-001", "SG-002", "SG-003", "SG-004"],
    "ec2_instances": ["EC2-001", "EC2-002"],
    "ebs_volumes": ["EBS-001", "EBS-002"],
    "snapshots": ["SNAP-001"],
    "elastic_ips": ["EIP-001"],
    "rds_instances": ["RDS-001", "RDS-002", "RDS-003", "RDS-004"],
    "dynamodb_tables": ["DDB-001", "DDB-002"],
    "iam_roles": ["IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005", "IAM-006", "IAM-007", "IAM-008"],
    "lambda_functions": ["LAM-001", "LAM-002"],
    "vpcs": ["VPC-001"],
    "internet_gateways": ["IGW-001"],
    "nat_gateways": ["NAT-001", "NAT-002"],
    "load_balancers": ["ELB-001", "ELB-002"],
}

RULE_REQUIRED_FIELDS = {
    "S3-001": ("is_empty",),
    "S3-002": ("name",),
    "S3-003": ("name",),
    "S3-004": ("name",),
    "S3-005": ("name",),
    "SG-001": ("ip_permissions",),
    "SG-002": ("ip_permissions",),
    "SG-003": ("ip_permissions",),
    "SG-004": ("ip_permissions",),
    "EC2-001": ("state",),
    "EC2-002": ("state", "http_tokens"),
    "EBS-001": ("encrypted",),
    "EBS-002": ("state",),
    "SNAP-001": ("volume_id",),
    "EIP-001": ("association_id",),
    "RDS-001": ("publicly_accessible",),
    "RDS-002": ("storage_encrypted",),
    "RDS-003": ("deletion_protection",),
    "RDS-004": ("backup_retention_period",),
    "DDB-001": ("sse_description",),
    "DDB-002": ("billing_mode", "item_count"),
    "IAM-001": ("inline_policies",),
    "IAM-002": ("inline_policies",),
    "IAM-003": ("attached_managed_policies",),
    "IAM-004": ("attached_managed_policies",),
    "IAM-005": ("trust_policy",),
    "IAM-006": ("inline_policies",),
    "IAM-007": ("attached_managed_policies",),
    "IAM-008": ("trust_policy",),
    "LAM-001": ("last_modified",),
    "LAM-002": ("runtime",),
    "VPC-001": ("is_default",),
    "IGW-001": ("attachments",),
    "NAT-001": ("state",),
    "NAT-002": ("state",),
    "ELB-001": ("scheme",),
    "ELB-002": ("type",),
}

# AWS APIs where None is valid, inspected evidence ("not configured").
NULL_IS_EVIDENCE = {
    "EIP-001": {"association_id"},
}


def get_rules_catalog() -> list[dict]:
    """Return the authoritative catalog of all deterministic checks for UI disclosure."""
    catalog = []
    for rule_id, meta in RULE_METADATA.items():
        catalog.append({
            "id": rule_id,
            "name": meta["name"],
            "service": meta["service"],
            "resourceType": meta["resource_type"],
            "severity": meta["severity"],
            "category": meta["category"],
            "whatItChecks": meta["what_it_checks"],
        })
    return catalog


def _extract_account_from_principal(principal_str: str) -> str | None:
    if not isinstance(principal_str, str):
        return None
    if principal_str.isdigit() and len(principal_str) == 12:
        return principal_str
    match = re.match(r"^arn:aws:iam::(\d{12}):", principal_str)
    return match.group(1) if match else None


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
        # Container-image Lambdas have no managed runtime string; that is valid.
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
    """Return explicit per-rule evaluation states for a resource."""
    rule_errors = rule_errors or {}
    results = []
    for rule_id in rule_ids:
        missing = _missing_rule_fields(raw, rule_id)
        if rule_id in rule_errors:
            status = "NOT_ASSESSED"
            reason = rule_errors[rule_id]
        elif missing:
            status = "NOT_ASSESSED"
            reason = "Missing required configuration: " + ", ".join(missing)
        elif any(issue.get("rule_id") == rule_id for issue in issues):
            status, reason = "VIOLATED", None
        else:
            status, reason = "PASSED", None
        check = {"rule_id": rule_id, "status": status}
        if reason:
            check["reason"] = reason
        results.append(check)

    unknown_count = sum(item["status"] == "NOT_ASSESSED" for item in results)
    state = "NOT_ASSESSED" if unknown_count == len(results) else "PARTIAL" if unknown_count else "ASSESSED"
    return {"status": state, "checks": results}


def _issue(
    rule_id: str,
    severity: str,
    title: str,
    why: str,
    evidence: dict,
    fix: str,
    what_found: str | None = None,
    what_checked: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    category: str | None = None,
) -> dict:
    meta = RULE_METADATA.get(rule_id, {})
    item = {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "what_found": what_found or meta.get("what_found") or title,
        "why": why,
        "what_checked": what_checked or meta.get("what_checked") or "Inspected AWS resource configuration.",
        "evidence": evidence,
        "fix": fix,
        "category": category or meta.get("category") or "Security",
        "source": "AWS API configuration",
        "message": title,
    }
    if resource_type:
        item["resource_type"] = resource_type
    if resource_id:
        item["resource_id"] = resource_id
    return item


def evaluate(
    session,
    resources: dict,
    account_id: str | None = None,
    scanner_statuses: list[dict] | None = None,
) -> dict:
    total = sum(len(v) for v in resources.values() if isinstance(v, list))
    if total == 0:
        return resources

    s3_client = session.client("s3") if session else None

    # Track regions where EBS volume discovery failed so we don't falsely mark snapshots orphaned.
    failed_ebs_regions = {
        s.get("region")
        for s in (scanner_statuses or [])
        if s.get("key") == "ebs_volumes" and s.get("status") not in ("COMPLETED",)
    }
    active_volume_ids = {v["id"] for v in resources.get("ebs_volumes", [])}

    for r_type, items in resources.items():
        if not isinstance(items, list):
            continue
        for r in items:
            raw = r.get("raw")
            if not isinstance(raw, dict):
                raw = {}
            rule_errors = dict(r.get("assessment_errors") or raw.get("_assessment_errors") or {})
            rule_ids = CHECKS_BY_RESOURCE.get(r_type, [])

            if not rule_ids:
                r["status"] = "NOT_ASSESSED"
                r["issues"] = []
                r["assessment"] = {
                    "status": "NOT_ASSESSED",
                    "checks": [],
                    "reason": "No checks are currently defined for this resource type.",
                }
                continue

            if not raw:
                r["status"] = "NOT_ASSESSED"
                r["issues"] = []
                r["assessment"] = _assessment(rule_ids, raw, [], rule_errors)
                continue

            issues = []

            # ------------------------------------------------------------------
            # S3 Buckets
            # ------------------------------------------------------------------
            if r_type == "s3_buckets":
                bucket_name = r["id"]

                # S3-001 — empty bucket
                if raw.get("is_empty") is True:
                    issues.append(_issue(
                        rule_id="S3-001",
                        severity="ORPHANED",
                        title="Empty S3 bucket",
                        why="An empty bucket serves no active storage purpose and adds account clutter.",
                        evidence={"Bucket": bucket_name, "Objects": "0"},
                        fix="If this bucket is no longer needed, delete it from the S3 console.",
                    ))

                if s3_client is None:
                    for rid in ("S3-002", "S3-003", "S3-004", "S3-005"):
                        rule_errors.setdefault(rid, "S3 client unavailable during evaluation")
                else:
                    # S3-002 — bucket policy public access
                    try:
                        pol_resp = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                        if pol_resp.get("PolicyStatus", {}).get("IsPublic", False):
                            issues.append(_issue(
                                rule_id="S3-002",
                                severity="CRITICAL",
                                title="S3 bucket is publicly accessible via bucket policy",
                                why="Anyone on the internet can read or write objects in this bucket.",
                                evidence={"Bucket": bucket_name, "AccessSource": "Bucket Policy", "PublicAccess": "True"},
                                fix="Remove or tighten the bucket policy to deny public access, and enable S3 Block Public Access.",
                            ))
                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "AWS error")
                        if code != "NoSuchBucketPolicy":
                            rule_errors["S3-002"] = f"Could not read bucket policy status: {code}"

                    # S3-003 — ACL public access
                    try:
                        acl_resp = s3_client.get_bucket_acl(Bucket=bucket_name)
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
                                why="The bucket Access Control List allows read or write access to anyone on the internet.",
                                evidence={"Bucket": bucket_name, "AccessSource": "ACL", "PublicGrantees": ", ".join(public_grants)},
                                fix="Disable ACLs (Bucket owner enforced) or remove public grants in S3 → Bucket → Permissions → ACL.",
                            ))
                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "AWS error")
                        rule_errors["S3-003"] = f"Could not read bucket ACL: {code}"

                    # S3-004 — encryption configuration readability check (AWS enforces SSE-S3 by default)
                    try:
                        s3_client.get_bucket_encryption(Bucket=bucket_name)
                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "AWS error")
                        if code != "ServerSideEncryptionConfigurationNotFoundError":
                            rule_errors["S3-004"] = f"Could not read bucket encryption configuration: {code}"

                    # S3-005 — Block Public Access
                    try:
                        pab_resp = s3_client.get_public_access_block(Bucket=bucket_name)
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
                                why="Without all four Block Public Access settings enabled, a future policy or ACL change could accidentally expose this bucket.",
                                evidence={"Bucket": bucket_name, "DisabledSettings": ", ".join(missing_pab)},
                                fix="Enable all four settings under S3 → Bucket → Permissions → Block public access.",
                            ))
                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "AWS error")
                        if code == "NoSuchPublicAccessBlockConfiguration":
                            issues.append(_issue(
                                rule_id="S3-005",
                                severity="WARNING",
                                title="S3 Block Public Access is not configured",
                                why="Without Block Public Access enabled, a future policy or ACL change could accidentally expose this bucket.",
                                evidence={"Bucket": bucket_name, "DisabledSettings": "All four settings missing"},
                                fix="Enable all four settings under S3 → Bucket → Permissions → Block public access.",
                            ))
                        else:
                            rule_errors["S3-005"] = f"Could not read Block Public Access settings: {code}"

            # ------------------------------------------------------------------
            # Security Groups
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
                                title="Security group allows all traffic from the internet",
                                why="Any host on the internet can attempt to connect to resources using this security group on any port.",
                                evidence={
                                    "SecurityGroup": r["id"],
                                    "Protocol": "All",
                                    "Ports": "All",
                                    "Source": cidr,
                                },
                                fix="Remove the all-traffic inbound rule and allow only the specific ports and trusted CIDRs your workload needs.",
                            ))
                        elif from_port is not None and to_port is not None:
                            if from_port <= 22 <= to_port:
                                port_range = "22" if from_port == to_port else f"{from_port}-{to_port}"
                                issues.append(_issue(
                                    rule_id="SG-002",
                                    severity="CRITICAL",
                                    title="SSH port (22) open to the internet",
                                    why="Exposing SSH to the entire internet enables automated brute-force and credential-stuffing attacks.",
                                    evidence={
                                        "SecurityGroup": r["id"],
                                        "Port": port_range,
                                        "Protocol": proto_label,
                                        "Source": cidr,
                                    },
                                    fix="Restrict port 22 to your specific office/VPN IP CIDR, or use AWS Systems Manager Session Manager instead of public SSH.",
                                ))

                            if from_port <= 3389 <= to_port:
                                port_range = "3389" if from_port == to_port else f"{from_port}-{to_port}"
                                issues.append(_issue(
                                    rule_id="SG-003",
                                    severity="CRITICAL",
                                    title="RDP port (3389) open to the internet",
                                    why="Exposing Windows Remote Desktop to the entire internet is a common ransomware and credential-attack entry point.",
                                    evidence={
                                        "SecurityGroup": r["id"],
                                        "Port": port_range,
                                        "Protocol": proto_label,
                                        "Source": cidr,
                                    },
                                    fix="Restrict port 3389 to your organization's IP address or connect privately via VPN / AWS Systems Manager.",
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
                                    why="Exposing database ports directly to the public internet lets external attackers target your data tier directly.",
                                    evidence={
                                        "SecurityGroup": r["id"],
                                        "ExposedPorts": ", ".join(exposed_db),
                                        "Protocol": proto_label,
                                        "Source": cidr,
                                    },
                                    fix="Change the inbound source from 0.0.0.0/0 (or ::/0) to the specific application security group ID or private VPC CIDR.",
                                ))

            # ------------------------------------------------------------------
            # EC2 Instances
            # ------------------------------------------------------------------
            elif r_type == "ec2_instances":
                ec2_state = str(raw.get("state", "")).lower()
                if ec2_state == "stopped":
                    issues.append(_issue(
                        rule_id="EC2-001",
                        severity="ORPHANED",
                        title="EC2 instance is stopped",
                        why="Stopped instances continue incurring charges for attached EBS volumes and any associated Elastic IPs.",
                        evidence={
                            "Instance": r["id"],
                            "InstanceType": raw.get("instance_type", "unknown"),
                            "State": "stopped",
                            "AttachedVolumes": str(len(raw.get("ebs_volumes") or [])),
                        },
                        fix="If this instance is no longer needed, take a final AMI/snapshot if required and terminate it to stop storage charges.",
                    ))

                http_tokens = raw.get("http_tokens")
                if ec2_state != "terminated" and http_tokens is not None and http_tokens != "required":
                    issues.append(_issue(
                        rule_id="EC2-002",
                        severity="WARNING",
                        title="EC2 instance does not enforce IMDSv2",
                        why="Allowing IMDSv1 makes instance IAM role credentials easier to steal through Server-Side Request Forgery (SSRF) vulnerabilities.",
                        evidence={
                            "Instance": r["id"],
                            "HttpTokens": str(http_tokens),
                            "Recommended": "required",
                        },
                        fix="Enforce IMDSv2: EC2 Console → Instance → Actions → Instance settings → Modify instance metadata options → IMDSv2 Required.",
                    ))

            # ------------------------------------------------------------------
            # EBS Volumes
            # ------------------------------------------------------------------
            elif r_type == "ebs_volumes":
                vol_state = str(raw.get("state", "")).lower()
                vol_size = raw.get("size")

                if raw.get("encrypted") is False:
                    issues.append(_issue(
                        rule_id="EBS-001",
                        severity="WARNING",
                        title="EBS volume is not encrypted",
                        why="Unencrypted block storage risks exposing sensitive data if snapshots or volumes are copied or accessed outside standard controls.",
                        evidence={
                            "Volume": r["id"],
                            "SizeGB": str(vol_size) if vol_size is not None else "unknown",
                            "Encrypted": "False",
                        },
                        fix="Create a snapshot of the volume, copy it with encryption enabled, and restore a new encrypted volume. Enable EBS encryption by default in EC2 settings.",
                    ))

                if vol_state == "available":
                    issues.append(_issue(
                        rule_id="EBS-002",
                        severity="ORPHANED",
                        title="Unattached EBS volume incurring storage charges",
                        why="This disk is not attached to any EC2 instance, yet AWS bills for its provisioned GB every month until deleted.",
                        evidence={
                            "Volume": r["id"],
                            "State": "available (unattached)",
                            "SizeGB": str(vol_size) if vol_size is not None else "unknown",
                            "VolumeType": str(raw.get("volume_type") or "unknown"),
                        },
                        fix="Verify the volume is no longer needed, create a final snapshot if you need a backup, then delete the volume from EC2 → Volumes.",
                    ))

            # ------------------------------------------------------------------
            # EBS Snapshots
            # ------------------------------------------------------------------
            elif r_type == "snapshots":
                vol_id = raw.get("volume_id")
                snap_region = r.get("region")
                if snap_region in failed_ebs_regions:
                    rule_errors["SNAP-001"] = "Could not verify parent volume because EBS volume discovery did not complete in this region."
                elif vol_id and vol_id not in active_volume_ids:
                    issues.append(_issue(
                        rule_id="SNAP-001",
                        severity="ORPHANED",
                        title="Orphaned snapshot (source volume deleted)",
                        why="The EBS volume this snapshot came from no longer exists. Abandoned snapshots accumulate monthly storage charges.",
                        evidence={
                            "Snapshot": r["id"],
                            "SourceVolumeId": vol_id,
                            "VolumeSizeGB": str(raw.get("volume_size") or "unknown"),
                        },
                        fix="Confirm this snapshot is not needed for disaster recovery or an active AMI, then delete it from EC2 → Snapshots.",
                    ))

            # ------------------------------------------------------------------
            # Elastic IPs
            # ------------------------------------------------------------------
            elif r_type == "elastic_ips":
                if not raw.get("association_id"):
                    issues.append(_issue(
                        rule_id="EIP-001",
                        severity="ORPHANED",
                        title="Unassociated Elastic IP incurring hourly charges",
                        why="AWS bills hourly for allocated public IPv4 addresses even when they are idle and unattached.",
                        evidence={
                            "ElasticIP": r["id"],
                            "PublicIp": str(raw.get("public_ip") or "unknown"),
                            "AssociationId": "None",
                        },
                        fix="If this static IP is no longer needed, release it in EC2 → Elastic IPs → Actions → Release Elastic IP address.",
                    ))

            # ------------------------------------------------------------------
            # RDS Instances
            # ------------------------------------------------------------------
            elif r_type == "rds_instances":
                engine = raw.get("engine", "unknown")

                if raw.get("publicly_accessible") is True:
                    issues.append(_issue(
                        rule_id="RDS-001",
                        severity="CRITICAL",
                        title="RDS database is publicly accessible",
                        why="A publicly accessible database can be reached from outside your VPC, exposing it to direct external attack attempts.",
                        evidence={
                            "Database": r["id"],
                            "Engine": engine,
                            "PubliclyAccessible": "True",
                        },
                        fix="Modify the RDS instance to disable 'Publicly accessible' and connect applications strictly within private VPC subnets.",
                    ))

                if raw.get("storage_encrypted") is False:
                    issues.append(_issue(
                        rule_id="RDS-002",
                        severity="WARNING",
                        title="RDS database storage is not encrypted",
                        why="Unencrypted database volumes and backups leave sensitive data unprotected at rest.",
                        evidence={
                            "Database": r["id"],
                            "Engine": engine,
                            "StorageEncrypted": "False",
                        },
                        fix="Take a snapshot, copy the snapshot with KMS encryption enabled, and restore to a new encrypted DB instance.",
                    ))

                if raw.get("deletion_protection") is False:
                    issues.append(_issue(
                        rule_id="RDS-003",
                        severity="WARNING",
                        title="RDS database has no deletion protection",
                        why="Without deletion protection, the database can be permanently deleted accidentally or by a compromised credential.",
                        evidence={
                            "Database": r["id"],
                            "Engine": engine,
                            "DeletionProtection": "Disabled",
                        },
                        fix="Enable deletion protection: RDS → Databases → Select DB → Modify → Enable deletion protection.",
                    ))

                backup_days = raw.get("backup_retention_period")
                if backup_days == 0:
                    issues.append(_issue(
                        rule_id="RDS-004",
                        severity="WARNING",
                        title="RDS automated backups are disabled",
                        why="With a 0-day retention period, point-in-time recovery is disabled if data is corrupted or accidentally dropped.",
                        evidence={
                            "Database": r["id"],
                            "Engine": engine,
                            "BackupRetentionDays": "0",
                        },
                        fix="Modify the RDS instance and set Backup retention period to at least 7 days (or your recovery policy).",
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
                        why="The table explicitly reports encryption at rest disabled.",
                        evidence={"Table": table_name, "SSEStatus": "DISABLED"},
                        fix="Enable server-side encryption for the table in DynamoDB → Table → Additional settings → Encryption at rest.",
                    ))

                if raw.get("billing_mode") == "PROVISIONED" and raw.get("item_count") == 0:
                    issues.append(_issue(
                        rule_id="DDB-002",
                        severity="ORPHANED",
                        title="Empty DynamoDB table with provisioned capacity",
                        why="A provisioned table with 0 items reserves read/write capacity units continuously and can generate unnecessary charges outside Free Tier.",
                        evidence={
                            "Table": table_name,
                            "BillingMode": "PROVISIONED",
                            "ItemCount": "0",
                            "RCU": str(raw.get("read_capacity_units") or "unknown"),
                            "WCU": str(raw.get("write_capacity_units") or "unknown"),
                        },
                        fix="Switch the table to On-Demand (PAY_PER_REQUEST) capacity mode, or delete the table if it is unused.",
                    ))

            # ------------------------------------------------------------------
            # IAM Roles
            # ------------------------------------------------------------------
            elif r_type == "iam_roles":
                role_name = raw.get("role_name", r["name"])

                # Inline policies
                seen_wildcard_action = False
                seen_broad_service_action = False
                inline_policies = raw.get("inline_policies")
                if isinstance(inline_policies, dict):
                    for policy_name, policy_document in inline_policies.items():
                        statement_list = policy_document.get("Statement", [])
                        if isinstance(statement_list, dict):
                            statement_list = [statement_list]

                        for statement in statement_list:
                            if statement.get("Effect") != "Allow":
                                continue

                            actions = statement.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]

                            resources_list = statement.get("Resource", [])
                            if isinstance(resources_list, str):
                                resources_list = [resources_list]

                            if ("*" in actions or "iam:*" in actions) and not seen_wildcard_action:
                                seen_wildcard_action = True
                                issues.append(_issue(
                                    rule_id="IAM-001",
                                    severity="CRITICAL",
                                    title="IAM role has unrestricted wildcard permissions",
                                    why="Granting Action: * or iam:* allows full administrative control or privilege escalation, violating least privilege.",
                                    evidence={
                                        "Role": role_name,
                                        "Policy": policy_name,
                                        "Action": "*" if "*" in actions else "iam:*",
                                        "Resource": ", ".join(resources_list[:5]),
                                    },
                                    fix="Replace wildcard actions with only the specific AWS actions this role actually needs.",
                                ))

                            broad_service_actions = [
                                a for a in actions if a.endswith(":*") and a not in ("iam:*", "*")
                            ]
                            if (
                                broad_service_actions
                                and "*" in resources_list
                                and not seen_wildcard_action
                                and not seen_broad_service_action
                            ):
                                seen_broad_service_action = True
                                issues.append(_issue(
                                    rule_id="IAM-006",
                                    severity="WARNING",
                                    title="IAM role grants broad service-level wildcards",
                                    why="Service wildcards (e.g. s3:*, ec2:*) on Resource: * grant full read, write, and delete rights across the entire service.",
                                    evidence={
                                        "Role": role_name,
                                        "Policy": policy_name,
                                        "Actions": ", ".join(broad_service_actions[:5]),
                                        "Resource": "*",
                                    },
                                    fix="Replace service wildcards with the exact API actions needed and scope Resource to specific ARNs.",
                                ))

                            if (
                                "*" in resources_list
                                and any(":" in a for a in actions)
                                and not any(a == "*" or a == "iam:*" or a.endswith(":*") for a in actions)
                            ):
                                issues.append(_issue(
                                    rule_id="IAM-002",
                                    severity="WARNING",
                                    title="IAM role inline policy applies to all resources (*)",
                                    why="Using Resource: * allows the role to operate on every resource of that service across the entire account.",
                                    evidence={
                                        "Role": role_name,
                                        "Policy": policy_name,
                                        "Actions": ", ".join(actions[:8]),
                                        "Resource": "*",
                                    },
                                    fix="Narrow the Resource field to specific ARNs wherever the AWS service supports resource-level permissions.",
                                ))

                # Attached managed policies
                attached_policies = raw.get("attached_managed_policies")
                if isinstance(attached_policies, list):
                    dangerous_managed = {
                        "arn:aws:iam::aws:policy/AdministratorAccess": (
                            "IAM-003",
                            "CRITICAL",
                            "IAM role has AdministratorAccess attached",
                            "AdministratorAccess grants unrestricted access to every AWS service and resource in the account.",
                            "Detach AdministratorAccess and attach a custom least-privilege policy limited to required actions.",
                        ),
                        "arn:aws:iam::aws:policy/IAMFullAccess": (
                            "IAM-004",
                            "WARNING",
                            "IAM role has IAMFullAccess attached",
                            "IAMFullAccess lets this role create or modify any IAM identity or policy, enabling full privilege escalation.",
                            "Detach IAMFullAccess and scope permissions to only the specific IAM operations required.",
                        ),
                        "arn:aws:iam::aws:policy/PowerUserAccess": (
                            "IAM-007",
                            "WARNING",
                            "IAM role has PowerUserAccess attached",
                            "PowerUserAccess grants full access to nearly all AWS services, which is overly broad for application roles.",
                            "Replace PowerUserAccess with a scoped policy listing only required service actions.",
                        ),
                    }
                    for pol in attached_policies:
                        pol_arn = pol.get("PolicyArn", "")
                        pol_name = pol.get("PolicyName", pol_arn)
                        if pol_arn in dangerous_managed:
                            rule_id, sev, title, why, fix_text = dangerous_managed[pol_arn]
                            issues.append(_issue(
                                rule_id=rule_id,
                                severity=sev,
                                title=title,
                                why=why,
                                evidence={"Role": role_name, "PolicyName": pol_name, "PolicyArn": pol_arn},
                                fix=fix_text,
                            ))

                # Trust relationship checks
                trust_doc = raw.get("trust_policy") or {}
                trust_statements = trust_doc.get("Statement", [])
                if isinstance(trust_statements, dict):
                    trust_statements = [trust_statements]

                # Derive role's own account ID from ARN if not passed explicitly
                role_own_account = account_id or _extract_account_from_principal(raw.get("arn", ""))

                for stmt in trust_statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal", {})
                    is_public = (
                        principal == "*"
                        or (isinstance(principal, dict) and principal.get("AWS") == "*")
                        or (isinstance(principal, dict) and principal.get("Service") == "*")
                    )
                    if is_public:
                        issues.append(_issue(
                            rule_id="IAM-005",
                            severity="CRITICAL",
                            title="IAM role trust policy allows anyone (*)",
                            why="A trust policy with Principal: * permits any AWS account or entity to assume this role and inherit its permissions.",
                            evidence={"Role": role_name, "Principal": "*"},
                            fix="Replace Principal: * in the trust policy with the exact AWS account ID, role ARN, or AWS service principal.",
                        ))
                        break

                    if isinstance(principal, dict) and "AWS" in principal:
                        aws_p = principal["AWS"]
                        aws_principals = aws_p if isinstance(aws_p, list) else [aws_p]
                        condition = stmt.get("Condition") or {}
                        has_ext_id = any(
                            k in ("StringEquals", "StringLike")
                            and any("sts:ExternalId" in str(ck) for ck in cv.keys())
                            for k, cv in condition.items()
                            if isinstance(cv, dict)
                        )
                        for p_arn in aws_principals:
                            trusted_account = _extract_account_from_principal(p_arn)
                            if not trusted_account:
                                continue
                            # Same-account trust does not require an ExternalId
                            if role_own_account and trusted_account == role_own_account:
                                continue
                            if not has_ext_id:
                                issues.append(_issue(
                                    rule_id="IAM-008",
                                    severity="WARNING",
                                    title="Cross-account trust policy missing ExternalId condition",
                                    why="Allowing another AWS account to assume this role without an sts:ExternalId condition exposes it to confused deputy attacks.",
                                    evidence={
                                        "Role": role_name,
                                        "TrustedPrincipal": p_arn,
                                        "MissingCondition": "sts:ExternalId",
                                    },
                                    fix="Add a StringEquals Condition requiring 'sts:ExternalId' to the role's trust relationship.",
                                ))
                                break

            # ------------------------------------------------------------------
            # Lambda Functions
            # ------------------------------------------------------------------
            elif r_type == "lambda_functions":
                fn_name = r["name"]
                last_mod = raw.get("last_modified")
                if last_mod:
                    try:
                        if "+" in last_mod:
                            time_part = last_mod.split("+")[0]
                            dt = datetime.datetime.strptime(
                                time_part, "%Y-%m-%dT%H:%M:%S.%f"
                            ).replace(tzinfo=datetime.timezone.utc)
                        else:
                            dt = datetime.datetime.strptime(last_mod, "%Y-%m-%dT%H:%M:%S.%f%z")
                        age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
                        if age_days > 90:
                            issues.append(_issue(
                                rule_id="LAM-001",
                                severity="WARNING",
                                title="Lambda function not updated in over 90 days",
                                why="Unmaintained functions often carry outdated dependencies or unused IAM permissions.",
                                evidence={
                                    "Function": fn_name,
                                    "LastModified": str(last_mod),
                                    "DaysSinceModified": str(age_days),
                                },
                                fix="Confirm this function is still needed. Update its dependencies/runtime or delete it if obsolete.",
                            ))
                    except Exception:
                        rule_errors["LAM-001"] = "Could not parse Lambda LastModified timestamp."

                runtime = raw.get("runtime")
                if runtime and runtime in DEPRECATED_LAMBDA_RUNTIMES:
                    issues.append(_issue(
                        rule_id="LAM-002",
                        severity="WARNING",
                        title=f"Lambda function uses deprecated runtime ({runtime})",
                        why="Deprecated runtimes no longer receive security patches or technical support from AWS.",
                        evidence={
                            "Function": fn_name,
                            "Runtime": runtime,
                        },
                        fix="Upgrade the function to a currently supported AWS Lambda runtime (e.g., python3.12, nodejs22.x) and redeploy.",
                    ))

            # ------------------------------------------------------------------
            # VPCs
            # ------------------------------------------------------------------
            elif r_type == "vpcs":
                vpc_id = r["id"]
                if raw.get("is_default") is True:
                    issues.append(_issue(
                        rule_id="VPC-001",
                        severity="WARNING",
                        title="Default VPC is present and active",
                        why="AWS default VPCs place all subnets directly on the public internet with permissive default routing.",
                        evidence={
                            "VpcId": vpc_id,
                            "IsDefault": "True",
                            "CidrBlock": str(raw.get("cidr_block", "unknown")),
                        },
                        fix="Deploy production workloads in a custom VPC with isolated private subnets and explicit route tables.",
                    ))

            # ------------------------------------------------------------------
            # Internet Gateways
            # ------------------------------------------------------------------
            elif r_type == "internet_gateways":
                igw_id = r["id"]
                attachments = raw.get("attachments", [])
                if len(attachments) == 0:
                    issues.append(_issue(
                        rule_id="IGW-001",
                        severity="ORPHANED",
                        title="Internet Gateway is not attached to any VPC",
                        why="This Internet Gateway is orphaned and serves no network routing purpose.",
                        evidence={"InternetGateway": igw_id, "Attachments": "0"},
                        fix="Attach the gateway to a VPC if needed, or delete it from VPC → Internet gateways.",
                    ))

            # ------------------------------------------------------------------
            # NAT Gateways
            # ------------------------------------------------------------------
            elif r_type == "nat_gateways":
                nat_id = r["id"]
                state = str(raw.get("state", "")).lower()
                if state == "failed":
                    issues.append(_issue(
                        rule_id="NAT-001",
                        severity="WARNING",
                        title="NAT Gateway is in a failed state",
                        why="A failed NAT Gateway cannot route outbound traffic from private subnets.",
                        evidence={"NatGateway": nat_id, "State": "failed"},
                        fix="Inspect VPC subnet/EIP quotas, recreate the NAT Gateway if needed, and update private route tables.",
                    ))
                elif state == "available":
                    issues.append(_issue(
                        rule_id="NAT-002",
                        severity="WARNING",
                        title="Active NAT Gateway incurs continuous hourly charges",
                        why="NAT Gateways are a leading source of unexpected AWS bills (charged hourly plus per-GB data processed even with minimal traffic).",
                        evidence={
                            "NatGateway": nat_id,
                            "State": "available",
                            "SubnetId": str(raw.get("subnet_id") or "unknown"),
                        },
                        fix="Verify private subnets actively require outbound internet access. Use free VPC Gateway Endpoints for S3/DynamoDB, or delete unused NAT Gateways.",
                    ))

            # ------------------------------------------------------------------
            # Load Balancers
            # ------------------------------------------------------------------
            elif r_type == "load_balancers":
                lb_name = r["name"]
                if raw.get("scheme") == "internet-facing":
                    issues.append(_issue(
                        rule_id="ELB-001",
                        severity="WARNING",
                        title="Load balancer is internet-facing",
                        why="An internet-facing load balancer exposes a public DNS endpoint; confirm external exposure is intentional.",
                        evidence={
                            "LoadBalancer": lb_name,
                            "Scheme": "internet-facing",
                            "Type": str(raw.get("type") or "unknown"),
                        },
                        fix="Confirm public exposure is intended and backed by HTTPS/TLS + strict security groups. Use 'internal' scheme for private services.",
                    ))

                if raw.get("type") == "classic":
                    issues.append(_issue(
                        rule_id="ELB-002",
                        severity="WARNING",
                        title="Legacy Classic Load Balancer detected",
                        why="Classic Load Balancers are a previous-generation resource that incur ongoing hourly charges and lack modern ALB/NLB features.",
                        evidence={"LoadBalancer": lb_name, "Type": "classic"},
                        fix="Migrate active traffic to an Application or Network Load Balancer, or delete the Classic Load Balancer if unused.",
                    ))

            # ------------------------------------------------------------------
            # Filter, enrich, deduplicate, and compute final status
            # ------------------------------------------------------------------
            issues = [
                issue
                for issue in issues
                if issue.get("rule_id") not in rule_errors
                and _has_rule_evidence(raw, issue.get("rule_id"))
            ]
            for issue in issues:
                issue.setdefault("resource_type", r.get("type", r_type))
                issue.setdefault("resource_id", r.get("id"))

            seen_rule_ids = set()
            unique_issues = []
            for issue in issues:
                if issue["rule_id"] not in seen_rule_ids:
                    seen_rule_ids.add(issue["rule_id"])
                    unique_issues.append(issue)

            r["issues"] = unique_issues
            assessment = _assessment(rule_ids, raw, unique_issues, rule_errors)
            r["assessment"] = assessment

            has_crit = any(i["severity"] == "CRITICAL" for i in r["issues"])
            has_warn = any(i["severity"] == "WARNING" for i in r["issues"])
            has_orph = any(i["severity"] == "ORPHANED" for i in r["issues"])

            if has_crit:
                r["status"] = "CRITICAL"
            elif has_warn:
                r["status"] = "WARNING"
            elif has_orph:
                r["status"] = "ORPHANED"
            else:
                r["status"] = "HEALTHY" if assessment["status"] == "ASSESSED" else "NOT_ASSESSED"

    return resources
