/**
 * securityChecksCatalog.js
 *
 * Authoritative fallback registry of all 37 deterministic checks implemented
 * in backend/scanner/misconfig.py. At runtime, DashboardScreen prefers
 * `scanResults.coverage.rules_catalog` directly from the backend when present,
 * falling back to SECURITY_CHECKS for cached sessions.
 *
 * IMPORTANT: `resourceType` uses the exact singular `resource.type` emitted by
 * each scanner (e.g., "security_group", "s3_bucket", "ebs_snapshot").
 */

export const SECURITY_CHECKS = [
  // ── Security Groups ────────────────────────────────────────────────────────
  { id: "SG-001", name: "Unrestricted Inbound Traffic (All Ports)", service: "EC2", resourceType: "security_group", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether inbound firewall rules allow all protocols and all ports from 0.0.0.0/0 or ::/0." },
  { id: "SG-002", name: "Unrestricted SSH Access (Port 22)", service: "EC2", resourceType: "security_group", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether inbound SSH (port 22) is exposed to the public internet (0.0.0.0/0 or ::/0)." },
  { id: "SG-003", name: "Unrestricted RDP Access (Port 3389)", service: "EC2", resourceType: "security_group", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether inbound Windows RDP (port 3389) is exposed to the public internet (0.0.0.0/0 or ::/0)." },
  { id: "SG-004", name: "Database Port Exposed to Internet", service: "EC2", resourceType: "security_group", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether common database ports (3306, 5432, 1433, 6379, 27017) are open to 0.0.0.0/0 or ::/0." },

  // ── S3 Buckets ─────────────────────────────────────────────────────────────
  { id: "S3-001", name: "Empty S3 Bucket", service: "S3", resourceType: "s3_bucket", severity: "ORPHANED", category: "Unused", whatItChecks: "Checks whether an S3 bucket contains zero objects and may be leftover clutter." },
  { id: "S3-002", name: "Public Access via Bucket Policy", service: "S3", resourceType: "s3_bucket", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether an S3 bucket policy permits public read or write access from the internet." },
  { id: "S3-003", name: "Public Access via Bucket ACL", service: "S3", resourceType: "s3_bucket", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether an S3 bucket ACL grants public access to AllUsers or AuthenticatedUsers." },
  { id: "S3-004", name: "Server-Side Encryption Configuration", service: "S3", resourceType: "s3_bucket", severity: "WARNING", category: "Security", whatItChecks: "Verifies S3 default server-side encryption configuration is readable and active (accounting for AWS default SSE-S3)." },
  { id: "S3-005", name: "Incomplete Block Public Access", service: "S3", resourceType: "s3_bucket", severity: "WARNING", category: "Security", whatItChecks: "Checks whether all 4 S3 Block Public Access settings are enabled to prevent accidental exposure." },

  // ── EC2 Instances ──────────────────────────────────────────────────────────
  { id: "EC2-001", name: "Stopped EC2 Instance", service: "EC2", resourceType: "ec2_instance", severity: "ORPHANED", category: "Cost Risk", whatItChecks: "Checks whether an EC2 instance is stopped while retaining attached EBS storage and Elastic IPs that continue generating charges." },
  { id: "EC2-002", name: "IMDSv2 Not Enforced", service: "EC2", resourceType: "ec2_instance", severity: "WARNING", category: "Security", whatItChecks: "Checks whether an active EC2 instance requires Instance Metadata Service v2 (HttpTokens=required)." },

  // ── EBS Volumes & Snapshots ────────────────────────────────────────────────
  { id: "EBS-001", name: "EBS Volume Unencrypted", service: "EC2", resourceType: "ebs_volume", severity: "WARNING", category: "Security", whatItChecks: "Checks whether an EBS block storage volume is encrypted at rest." },
  { id: "EBS-002", name: "Unattached EBS Volume", service: "EC2", resourceType: "ebs_volume", severity: "ORPHANED", category: "Cost Risk", whatItChecks: "Checks whether an EBS volume is unattached ('available') and incurring ongoing storage charges." },
  { id: "SNAP-001", name: "Orphaned EBS Snapshot", service: "EC2", resourceType: "ebs_snapshot", severity: "ORPHANED", category: "Cost Risk", whatItChecks: "Checks whether an EBS snapshot's source volume has been deleted while the snapshot continues incurring storage charges." },

  // ── Elastic IPs ────────────────────────────────────────────────────────────
  { id: "EIP-001", name: "Unassociated Elastic IP", service: "EC2", resourceType: "elastic_ip", severity: "ORPHANED", category: "Cost Risk", whatItChecks: "Checks whether an Elastic IP address is unattached, incurring hourly IPv4 charges." },

  // ── RDS Databases ──────────────────────────────────────────────────────────
  { id: "RDS-001", name: "Publicly Accessible Database", service: "RDS", resourceType: "rds_instance", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether an RDS instance has PubliclyAccessible enabled instead of being private." },
  { id: "RDS-002", name: "Database Storage Unencrypted", service: "RDS", resourceType: "rds_instance", severity: "WARNING", category: "Security", whatItChecks: "Checks whether an RDS database storage volume is encrypted at rest." },
  { id: "RDS-003", name: "Database Deletion Protection Disabled", service: "RDS", resourceType: "rds_instance", severity: "WARNING", category: "Reliability", whatItChecks: "Checks whether accidental deletion protection is enabled on RDS databases." },
  { id: "RDS-004", name: "Automated Backups Disabled", service: "RDS", resourceType: "rds_instance", severity: "WARNING", category: "Reliability", whatItChecks: "Checks whether an RDS instance has automated backups disabled (BackupRetentionPeriod = 0)." },

  // ── DynamoDB Tables ────────────────────────────────────────────────────────
  { id: "DDB-001", name: "DynamoDB Encryption Disabled", service: "DynamoDB", resourceType: "dynamodb_table", severity: "WARNING", category: "Security", whatItChecks: "Checks whether a DynamoDB table reports encryption at rest explicitly disabled." },
  { id: "DDB-002", name: "Empty Provisioned DynamoDB Table", service: "DynamoDB", resourceType: "dynamodb_table", severity: "ORPHANED", category: "Cost Risk", whatItChecks: "Checks whether a provisioned-capacity DynamoDB table contains 0 items and may incur unnecessary charges." },

  // ── IAM Roles ──────────────────────────────────────────────────────────────
  { id: "IAM-001", name: "Unrestricted Wildcard Action (*)", service: "IAM", resourceType: "iam_role", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether an inline IAM policy allows Action: * or iam:*." },
  { id: "IAM-002", name: "Unrestricted Resource Scope (*)", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security", whatItChecks: "Checks whether inline IAM policy actions apply to all resources (Resource: *)." },
  { id: "IAM-003", name: "AdministratorAccess Managed Policy", service: "IAM", resourceType: "iam_role", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether the AWS-managed AdministratorAccess policy is attached to a role." },
  { id: "IAM-004", name: "IAMFullAccess Managed Policy", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security", whatItChecks: "Checks whether the IAMFullAccess managed policy is attached, enabling privilege escalation." },
  { id: "IAM-005", name: "Public Role Trust Relationship", service: "IAM", resourceType: "iam_role", severity: "CRITICAL", category: "Security", whatItChecks: "Checks whether an IAM role trust policy allows anyone (Principal: *) to assume the role." },
  { id: "IAM-006", name: "Broad Service-Level Wildcard Actions", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security", whatItChecks: "Checks whether inline policy statements grant service wildcards (e.g. s3:*, ec2:*) on Resource: *." },
  { id: "IAM-007", name: "PowerUserAccess Managed Policy", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security", whatItChecks: "Checks whether the broad PowerUserAccess managed policy is attached to a role." },
  { id: "IAM-008", name: "Cross-Account Trust Missing ExternalId", service: "IAM", resourceType: "iam_role", severity: "WARNING", category: "Security", whatItChecks: "Checks whether cross-account trust policies enforce an sts:ExternalId condition." },

  // ── Lambda Functions ───────────────────────────────────────────────────────
  { id: "LAM-001", name: "Stale Lambda Function (>90 Days)", service: "Lambda", resourceType: "lambda_function", severity: "WARNING", category: "Hygiene", whatItChecks: "Checks whether a Lambda function has not been updated in over 90 days." },
  { id: "LAM-002", name: "Deprecated Lambda Runtime", service: "Lambda", resourceType: "lambda_function", severity: "WARNING", category: "Security", whatItChecks: "Checks whether a Lambda function uses an end-of-life runtime that no longer receives AWS security patches." },

  // ── VPC & Networking ───────────────────────────────────────────────────────
  { id: "VPC-001", name: "Default VPC Present", service: "VPC", resourceType: "vpc", severity: "WARNING", category: "Security", whatItChecks: "Checks whether the AWS default VPC is active with permissive default networking." },
  { id: "IGW-001", name: "Unattached Internet Gateway", service: "VPC", resourceType: "internet_gateway", severity: "ORPHANED", category: "Unused", whatItChecks: "Checks whether an Internet Gateway exists without being attached to any VPC." },
  { id: "NAT-001", name: "Failed NAT Gateway", service: "VPC", resourceType: "nat_gateway", severity: "WARNING", category: "Reliability", whatItChecks: "Checks whether a NAT Gateway is in a failed state and unable to route traffic." },
  { id: "NAT-002", name: "Active NAT Gateway (Ongoing Charge Risk)", service: "VPC", resourceType: "nat_gateway", severity: "WARNING", category: "Cost Risk", whatItChecks: "Flags active NAT Gateways because they incur continuous hourly and per-GB data processing charges." },

  // ── Elastic Load Balancing ─────────────────────────────────────────────────
  { id: "ELB-001", name: "Internet-Facing Load Balancer", service: "ELB", resourceType: "load_balancer", severity: "WARNING", category: "Security", whatItChecks: "Checks whether a load balancer is internet-facing so you can confirm public exposure is intentional." },
  { id: "ELB-002", name: "Legacy Classic Load Balancer", service: "ELB", resourceType: "load_balancer", severity: "WARNING", category: "Cost Risk", whatItChecks: "Checks whether a legacy Classic Load Balancer (ELBv1) is running and incurring hourly charges." },
];

/**
 * Evaluate the live scan status of a deterministic check against scanned resources.
 */
export function evaluateCheckStatus(check, allResources = []) {
  const applicableResources = allResources.filter((r) => r.type === check.resourceType);

  if (applicableResources.length === 0) {
    return {
      status: "NOT_APPLICABLE",
      flaggedCount: 0,
      notAssessedCount: 0,
      flaggedResources: [],
      label: "No resources in scan",
    };
  }

  const flagged = [];
  let notAssessedCount = 0;

  for (const r of applicableResources) {
    const issues = r.issues || [];
    const hasRule = issues.some((i) => typeof i === "object" && i.rule_id === check.id);
    if (hasRule) {
      flagged.push({ id: r.id, name: r.name });
      continue;
    }

    const perRuleCheck = r.assessment?.checks?.find((c) => c.rule_id === check.id);
    if (perRuleCheck && perRuleCheck.status === "NOT_ASSESSED") {
      notAssessedCount++;
    }
  }

  if (flagged.length > 0) {
    return {
      status: "VIOLATED",
      flaggedCount: flagged.length,
      notAssessedCount,
      flaggedResources: flagged,
      label: `${flagged.length} resource${flagged.length > 1 ? "s" : ""} flagged`,
    };
  }

  if (notAssessedCount === applicableResources.length) {
    return {
      status: "NOT_ASSESSED",
      flaggedCount: 0,
      notAssessedCount,
      flaggedResources: [],
      label: `Could not evaluate (${notAssessedCount})`,
    };
  }

  const evaluatedCount = applicableResources.length - notAssessedCount;
  return {
    status: "PASSED",
    flaggedCount: 0,
    notAssessedCount,
    flaggedResources: [],
    label:
      notAssessedCount > 0
        ? `Passed (${evaluatedCount} evaluated, ${notAssessedCount} unassessed)`
        : `Passed (${applicableResources.length} evaluated)`,
  };
}
