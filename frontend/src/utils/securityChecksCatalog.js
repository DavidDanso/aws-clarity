/**
 * securityChecksCatalog.js
 *
 * Centralized registry of all 24 security checks implemented by AWS Clarity
 * in backend/scanner/misconfig.py.
 *
 * Each check describes:
 * - id: Standard rule identifier (e.g. SG-002, S3-002)
 * - name: Human-readable check title
 * - service: Applicable AWS service
 * - resourceType: Internal collection key
 * - severity: CRITICAL | WARNING | ORPHANED
 * - whatItChecks: Plain-English explanation of the security check
 */

export const SECURITY_CHECKS = [
  // ── Security Groups ──────────────────────────────────────────────────────────
  {
    id: "SG-001",
    name: "Unrestricted Inbound Traffic (All Ports)",
    service: "Security Groups",
    resourceType: "security_groups",
    severity: "CRITICAL",
    whatItChecks: "Checks whether inbound firewall rules allow all protocols and all ports from 0.0.0.0/0 or ::/0.",
  },
  {
    id: "SG-002",
    name: "Unrestricted SSH Access (Port 22)",
    service: "Security Groups",
    resourceType: "security_groups",
    severity: "CRITICAL",
    whatItChecks: "Checks whether inbound SSH (port 22) is exposed to the public internet (0.0.0.0/0 or ::/0).",
  },
  {
    id: "SG-003",
    name: "Unrestricted RDP Access (Port 3389)",
    service: "Security Groups",
    resourceType: "security_groups",
    severity: "CRITICAL",
    whatItChecks: "Checks whether inbound Windows RDP (port 3389) is exposed to the public internet (0.0.0.0/0 or ::/0).",
  },

  // ── S3 Buckets ───────────────────────────────────────────────────────────────
  {
    id: "S3-001",
    name: "Empty S3 Bucket",
    service: "S3",
    resourceType: "s3_buckets",
    severity: "ORPHANED",
    whatItChecks: "Checks whether an S3 bucket contains zero objects and serves no active storage purpose.",
  },
  {
    id: "S3-002",
    name: "Public Access via Bucket Policy",
    service: "S3",
    resourceType: "s3_buckets",
    severity: "CRITICAL",
    whatItChecks: "Checks whether an S3 bucket policy permits public read or write access from the internet.",
  },
  {
    id: "S3-003",
    name: "Public Access via Bucket ACL",
    service: "S3",
    resourceType: "s3_buckets",
    severity: "CRITICAL",
    whatItChecks: "Checks whether an S3 bucket Access Control List (ACL) grants public access to AllUsers or AuthenticatedUsers.",
  },
  {
    id: "S3-004",
    name: "Default Encryption Disabled",
    service: "S3",
    resourceType: "s3_buckets",
    severity: "WARNING",
    whatItChecks: "Checks whether server-side encryption (SSE-S3 or SSE-KMS) is enabled by default for new objects in the bucket.",
  },
  {
    id: "S3-005",
    name: "Incomplete Block Public Access",
    service: "S3",
    resourceType: "s3_buckets",
    severity: "WARNING",
    whatItChecks: "Checks whether all 4 S3 Block Public Access settings are actively enabled to prevent accidental exposure.",
  },

  // ── RDS Databases ────────────────────────────────────────────────────────────
  {
    id: "RDS-001",
    name: "Publicly Accessible Database",
    service: "RDS",
    resourceType: "rds_instances",
    severity: "CRITICAL",
    whatItChecks: "Checks whether an RDS instance has public IP exposure enabled instead of being restricted to a private subnet.",
  },
  {
    id: "RDS-002",
    name: "Database Storage Unencrypted",
    service: "RDS",
    resourceType: "rds_instances",
    severity: "WARNING",
    whatItChecks: "Checks whether an RDS database storage volume is encrypted at rest.",
  },
  {
    id: "RDS-003",
    name: "Database Deletion Protection Disabled",
    service: "RDS",
    resourceType: "rds_instances",
    severity: "WARNING",
    whatItChecks: "Checks whether accidental deletion protection is enabled on production RDS databases.",
  },

  // ── EBS Volumes ──────────────────────────────────────────────────────────────
  {
    id: "EBS-001",
    name: "EBS Volume Unencrypted",
    service: "EBS",
    resourceType: "ebs_volumes",
    severity: "WARNING",
    whatItChecks: "Checks whether an EBS block storage volume is encrypted at rest.",
  },
  {
    id: "EBS-002",
    name: "Unattached EBS Volume",
    service: "EBS",
    resourceType: "ebs_volumes",
    severity: "ORPHANED",
    whatItChecks: "Checks whether an EBS volume is in 'available' state and not attached to any compute instance.",
  },

  // ── IAM Roles ────────────────────────────────────────────────────────────────
  {
    id: "IAM-001",
    name: "Unrestricted Wildcard Action (*)",
    service: "IAM",
    resourceType: "iam_roles",
    severity: "CRITICAL",
    whatItChecks: "Checks whether an inline IAM policy statement allows full administrative wildcard action (Action: *).",
  },
  {
    id: "IAM-002",
    name: "Unrestricted Resource Scope (*)",
    service: "IAM",
    resourceType: "iam_roles",
    severity: "WARNING",
    whatItChecks: "Checks whether IAM policy actions apply to all account resources (Resource: *) without ARN restriction.",
  },
  {
    id: "IAM-003",
    name: "AdministratorAccess Managed Policy",
    service: "IAM",
    resourceType: "iam_roles",
    severity: "CRITICAL",
    whatItChecks: "Checks whether the full AWS-managed AdministratorAccess policy is attached to an IAM role.",
  },
  {
    id: "IAM-004",
    name: "IAMFullAccess Managed Policy",
    service: "IAM",
    resourceType: "iam_roles",
    severity: "WARNING",
    whatItChecks: "Checks whether the IAMFullAccess managed policy is attached, enabling potential privilege escalation.",
  },
  {
    id: "IAM-005",
    name: "Public Role Trust Relationship",
    service: "IAM",
    resourceType: "iam_roles",
    severity: "CRITICAL",
    whatItChecks: "Checks whether an IAM role's trust policy allows anyone on the internet (Principal: *) to assume the role.",
  },
  {
    id: "IAM-006",
    name: "Broad Service-Level Wildcard Actions",
    service: "IAM",
    resourceType: "iam_roles",
    severity: "WARNING",
    whatItChecks: "Checks whether policy statements grant service-wide wildcards (e.g. s3:*, ec2:*) combined with Resource: *.",
  },
  {
    id: "IAM-007",
    name: "PowerUserAccess Managed Policy",
    service: "IAM",
    resourceType: "iam_roles",
    severity: "WARNING",
    whatItChecks: "Checks whether the broad PowerUserAccess managed policy is attached to an IAM role.",
  },
  {
    id: "IAM-008",
    name: "Cross-Account Trust Missing ExternalId",
    service: "IAM",
    resourceType: "iam_roles",
    severity: "WARNING",
    whatItChecks: "Checks whether cross-account trust policies enforce an sts:ExternalId condition against confused deputy attacks.",
  },

  // ── EC2 Instances ────────────────────────────────────────────────────────────
  {
    id: "EC2-001",
    name: "Stopped EC2 Instance",
    service: "EC2",
    resourceType: "ec2_instances",
    severity: "ORPHANED",
    whatItChecks: "Checks whether an EC2 instance is in stopped state while retaining attached storage volumes and elastic IPs.",
  },

  // ── Elastic IPs ──────────────────────────────────────────────────────────────
  {
    id: "EIP-001",
    name: "Unassociated Elastic IP",
    service: "EC2 (VPC)",
    resourceType: "elastic_ips",
    severity: "ORPHANED",
    whatItChecks: "Checks whether a public Elastic IP address is allocated without an active network interface or instance association.",
  },

  // ── Snapshots ────────────────────────────────────────────────────────────────
  {
    id: "SNAP-001",
    name: "Orphan EBS Snapshot",
    service: "EBS",
    resourceType: "snapshots",
    severity: "ORPHANED",
    whatItChecks: "Checks whether an EBS snapshot's source volume has been deleted or no longer exists in the account.",
  },
];

/**
 * Evaluate the live scan status of a specific security check against scanned resources.
 *
 * @param {Object} check - An entry from SECURITY_CHECKS
 * @param {Array} allResources - Flat list of all resources returned from the scan
 * @returns {{
 *   status: "VIOLATED" | "PASSED" | "NOT_APPLICABLE",
 *   flaggedCount: number,
 *   flaggedResources: Array<{ id: string, name: string }>
 * }}
 */
export function evaluateCheckStatus(check, allResources = []) {
  // Find all resources matching this check's applicable type
  const applicableResources = allResources.filter(r => r.type === check.resourceType);

  if (applicableResources.length === 0) {
    return {
      status: "NOT_APPLICABLE",
      flaggedCount: 0,
      flaggedResources: [],
      label: "No resources scanned",
    };
  }

  // Find any applicable resource that has an issue with this check's rule_id
  const flagged = [];
  for (const r of applicableResources) {
    const issues = r.issues || [];
    const hasRule = issues.some(i => (typeof i === "object" ? i.rule_id === check.id : false));
    if (hasRule) {
      flagged.push({ id: r.id, name: r.name });
    }
  }

  if (flagged.length > 0) {
    return {
      status: "VIOLATED",
      flaggedCount: flagged.length,
      flaggedResources: flagged,
      label: `${flagged.length} resource${flagged.length > 1 ? "s" : ""} flagged`,
    };
  }

  return {
    status: "PASSED",
    flaggedCount: 0,
    flaggedResources: [],
    label: `Passed (${applicableResources.length} evaluated)`,
  };
}
