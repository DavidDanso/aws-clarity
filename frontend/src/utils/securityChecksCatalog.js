/**
 * securityChecksCatalog.js
 *
 * Authoritative fallback registry of all 43 deterministic checks across
 * AWS Clarity's 10 supported v1 services. At runtime, DashboardScreen prefers
 * `scanResults.coverage.rules_catalog` returned directly from the backend.
 */

export const SECURITY_CHECKS = [
  // EC2
  { id: "SG-001", name: "Unrestricted Inbound Traffic (All Ports)", service: "EC2", resourceType: "security_group", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether inbound firewall rules allow all protocols (-1) and all ports from 0.0.0.0/0 or ::/0." },
  { id: "SG-002", name: "Unrestricted SSH Access (Port 22)", service: "EC2", resourceType: "security_group", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether inbound SSH (port 22) is exposed to 0.0.0.0/0 or ::/0." },
  { id: "SG-003", name: "Unrestricted RDP Access (Port 3389)", service: "EC2", resourceType: "security_group", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether inbound Windows RDP (port 3389) is exposed to 0.0.0.0/0 or ::/0." },
  { id: "SG-004", name: "Database Port Exposed to Internet", service: "EC2", resourceType: "security_group", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether common database ports (3306, 5432, 1433, 6379, 27017) are open to 0.0.0.0/0 or ::/0." },
  { id: "EC2-001", name: "Stopped EC2 Instance", service: "EC2", resourceType: "ec2_instance", severity: "UNUSED", category: "Potential Cost Waste", whatItChecks: "Checks whether an EC2 instance is stopped while retaining attached EBS storage and Elastic IPs." },
  { id: "EC2-002", name: "IMDSv2 Not Enforced", service: "EC2", resourceType: "ec2_instance", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether an active EC2 instance enforces IMDSv2 (HttpTokens=required)." },
  { id: "EIP-001", name: "Unassociated Elastic IP", service: "EC2", resourceType: "elastic_ip", severity: "UNUSED", category: "Potential Cost Waste", whatItChecks: "Checks whether an allocated Elastic IP is unattached and incurring hourly public IPv4 charges." },

  // VPC
  { id: "VPC-001", name: "Publicly Exposed Workloads in Default VPC", service: "VPC", resourceType: "vpc", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether a default VPC actively hosts public-facing EC2 or publicly accessible RDS workloads (empty default VPCs are not flagged)." },
  { id: "IGW-001", name: "Unattached Internet Gateway", service: "VPC", resourceType: "internet_gateway", severity: "UNUSED", category: "Operational Concern", whatItChecks: "Checks whether an Internet Gateway exists without being attached to any VPC." },
  { id: "NAT-001", name: "Failed NAT Gateway", service: "VPC", resourceType: "nat_gateway", severity: "WARNING", category: "Operational Concern", whatItChecks: "Checks whether a NAT Gateway is in a failed state." },
  { id: "NAT-002", name: "Active NAT Gateway (Review Ongoing Cost)", service: "VPC", resourceType: "nat_gateway", severity: "INFO", category: "Potential Cost Waste", whatItChecks: "Informational cost review for active NAT Gateways because they incur continuous hourly and per-GB data-processing charges." },

  // S3
  { id: "S3-002", name: "Public Access via Bucket Policy", service: "S3", resourceType: "s3_bucket", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether an S3 bucket policy permits public read or write access." },
  { id: "S3-003", name: "Public Access via Bucket ACL", service: "S3", resourceType: "s3_bucket", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether an S3 bucket ACL grants public access to AllUsers or AuthenticatedUsers." },
  { id: "S3-004", name: "Server-Side Encryption Configuration", service: "S3", resourceType: "s3_bucket", severity: "WARNING", category: "Security Risk", whatItChecks: "Verifies S3 default server-side encryption configuration is readable and active (respecting AWS default SSE-S3)." },
  { id: "S3-005", name: "Incomplete Block Public Access", service: "S3", resourceType: "s3_bucket", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether all 4 S3 Block Public Access controls are enabled." },

  // IAM
  { id: "IAM-001", name: "Unrestricted Admin Wildcard Policy", service: "IAM", resourceType: "iam_role", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether an inline role policy grants Action: *, iam:*, or NotAction on Resource: * without scoping conditions." },
  { id: "IAM-002", name: "Unscoped Write/Destructive Actions on Resource: *", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether write/mutate actions apply to Resource: * without scoping conditions (read-only Describe/List/Get actions excluded)." },
  { id: "IAM-003", name: "AdministratorAccess Managed Policy Attached", service: "IAM", resourceType: "iam_role", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether AWS-managed AdministratorAccess is attached to a customer-managed IAM role." },
  { id: "IAM-004", name: "IAMFullAccess Managed Policy Attached", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether IAMFullAccess is attached to a customer-managed IAM role." },
  { id: "IAM-005", name: "Unrestricted Public Role Trust Policy", service: "IAM", resourceType: "iam_role", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether an IAM role trust policy allows Principal: * without scoping conditions." },
  { id: "IAM-006", name: "Unscoped Service-Wide Wildcard Actions", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether inline policies grant service wildcards (e.g. s3:*, ec2:*) on Resource: * without conditions." },
  { id: "IAM-007", name: "PowerUserAccess Managed Policy Attached", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether PowerUserAccess is attached to a customer-managed IAM role." },
  { id: "IAM-008", name: "Cross-Account Trust Missing ExternalId / Org Condition", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether external cross-account trust policies enforce sts:ExternalId or aws:PrincipalOrgID." },
  { id: "IAM-009", name: "IAM User Missing MFA", service: "IAM", resourceType: "iam_user", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether an IAM user with console sign-in activity or admin privileges has MFA enabled." },
  { id: "IAM-010", name: "Long-Lived Active IAM Access Key (>90 Days)", service: "IAM", resourceType: "iam_user", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether an IAM user has an Active static access key older than 90 days (age alone does not indicate compromise)." },
  { id: "IAM-011", name: "IAM User Directly Attached AdministratorAccess", service: "IAM", resourceType: "iam_user", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether an IAM user has AdministratorAccess or Action: * attached directly." },

  // Lambda
  { id: "LAM-001", name: "Lambda Function Unmodified >90 Days (Review)", service: "Lambda", resourceType: "lambda_function", severity: "INFO", category: "Operational Concern", whatItChecks: "Informational check noting whether a Lambda function has not been updated in over 90 days (stable functions are not automatically unhealthy)." },
  { id: "LAM-002", name: "Deprecated Lambda Runtime", service: "Lambda", resourceType: "lambda_function", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether a Lambda function uses a deprecated runtime." },

  // RDS
  { id: "RDS-001", name: "Publicly Accessible RDS Database", service: "RDS", resourceType: "rds_instance", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether an RDS instance has PubliclyAccessible enabled." },
  { id: "RDS-002", name: "RDS Storage Unencrypted", service: "RDS", resourceType: "rds_instance", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether RDS storage is encrypted at rest." },
  { id: "RDS-003", name: "RDS Deletion Protection Disabled", service: "RDS", resourceType: "rds_instance", severity: "WARNING", category: "Operational Concern", whatItChecks: "Checks whether deletion protection is enabled on RDS databases." },
  { id: "RDS-004", name: "RDS Automated Backups Disabled", service: "RDS", resourceType: "rds_instance", severity: "WARNING", category: "Operational Concern", whatItChecks: "Checks whether RDS automated backups are disabled (BackupRetentionPeriod = 0)." },

  // DynamoDB
  { id: "DDB-001", name: "DynamoDB Encryption Disabled", service: "DynamoDB", resourceType: "dynamodb_table", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether a DynamoDB table explicitly reports encryption disabled (AWS-owned default encryption passes)." },
  { id: "DDB-002", name: "Empty Provisioned DynamoDB Table", service: "DynamoDB", resourceType: "dynamodb_table", severity: "UNUSED", category: "Potential Cost Waste", whatItChecks: "Checks whether a PROVISIONED-capacity DynamoDB table holds 0 items." },

  // EBS
  { id: "EBS-001", name: "EBS Volume Unencrypted", service: "EBS", resourceType: "ebs_volume", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether an EBS volume is encrypted at rest." },
  { id: "EBS-002", name: "Unattached EBS Volume", service: "EBS", resourceType: "ebs_volume", severity: "UNUSED", category: "Potential Cost Waste", whatItChecks: "Checks whether an EBS volume is in 'available' state (unattached)." },
  { id: "SNAP-001", name: "EBS Snapshot Without Original Volume (Review)", service: "EBS", resourceType: "ebs_snapshot", severity: "INFO", category: "Potential Cost Waste", whatItChecks: "Informational review for snapshots whose original volume no longer exists (may be intentional backups or AMI snapshots)." },

  // CloudWatch
  { id: "CW-001", name: "CloudWatch Alarm Actions Disabled", service: "CloudWatch", resourceType: "cloudwatch_alarm", severity: "WARNING", category: "Operational Concern", whatItChecks: "Checks whether a CloudWatch alarm has alarm actions disabled." },
  { id: "CW-002", name: "CloudWatch Alarm in INSUFFICIENT_DATA State (Review)", service: "CloudWatch", resourceType: "cloudwatch_alarm", severity: "INFO", category: "Operational Concern", whatItChecks: "Informational check noting whether an alarm is in INSUFFICIENT_DATA (normal for sparse metrics; not automatically a failure)." },
  { id: "CW-003", name: "CloudWatch Log Group Set to Never Expire", service: "CloudWatch", resourceType: "cloudwatch_log_group", severity: "WARNING", category: "Potential Cost Waste", whatItChecks: "Checks whether a CloudWatch Log Group has no retention policy configured." },

  // CloudTrail
  { id: "CT-001", name: "CloudTrail Trail Logging Disabled", service: "CloudTrail", resourceType: "cloudtrail_trail", severity: "CRITICAL", category: "Security Risk", whatItChecks: "Checks whether a CloudTrail trail has logging actively turned on." },
  { id: "CT-002", name: "CloudTrail Trail Not Multi-Region", service: "CloudTrail", resourceType: "cloudtrail_trail", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether a CloudTrail trail captures API activity across all AWS regions." },
  { id: "CT-003", name: "CloudTrail Log File Validation Disabled", service: "CloudTrail", resourceType: "cloudtrail_trail", severity: "WARNING", category: "Security Risk", whatItChecks: "Checks whether CloudTrail cryptographic log file integrity validation is enabled." },
];

/**
 * Evaluate the live scan status of a deterministic check against scanned resources.
 * Status values: VIOLATED | REVIEW | PASSED | CHECK_FAILED | NOT_APPLICABLE
 */
export function evaluateCheckStatus(check, allResources = []) {
  const applicableResources = allResources.filter((r) => r.type === check.resourceType);

  if (applicableResources.length === 0) {
    return {
      status: "NOT_APPLICABLE",
      flaggedCount: 0,
      failedCount: 0,
      flaggedResources: [],
      label: "No resources in account",
    };
  }

  const flagged = [];
  const reviewOnly = [];
  let failedCount = 0;

  for (const r of applicableResources) {
    const issues = r.issues || [];
    const matching = issues.find((i) => typeof i === "object" && i.rule_id === check.id);
    if (matching) {
      if (matching.severity === "INFO") {
        reviewOnly.push({ id: r.id, name: r.name });
      } else {
        flagged.push({ id: r.id, name: r.name });
      }
      continue;
    }

    const perRuleCheck = r.assessment?.checks?.find((c) => c.rule_id === check.id);
    if (perRuleCheck && perRuleCheck.status === "CHECK_FAILED") {
      failedCount++;
    }
  }

  if (flagged.length > 0) {
    return {
      status: "VIOLATED",
      flaggedCount: flagged.length,
      failedCount,
      flaggedResources: flagged,
      label: `${flagged.length} resource${flagged.length > 1 ? "s" : ""} flagged`,
    };
  }

  if (reviewOnly.length > 0) {
    return {
      status: "REVIEW",
      flaggedCount: reviewOnly.length,
      failedCount,
      flaggedResources: reviewOnly,
      label: `${reviewOnly.length} for review`,
    };
  }

  if (failedCount === applicableResources.length) {
    return {
      status: "CHECK_FAILED",
      flaggedCount: 0,
      failedCount,
      flaggedResources: [],
      label: `Check failed (${failedCount})`,
    };
  }

  const passedCount = applicableResources.length - failedCount;
  return {
    status: "PASSED",
    flaggedCount: 0,
    failedCount,
    flaggedResources: [],
    label:
      failedCount > 0
        ? `Passed (${passedCount} verified, ${failedCount} failed)`
        : `Passed (${applicableResources.length} verified)`,
  };
}
