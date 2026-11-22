import { SERVICE_COVERAGE_MATRIX } from "../utils/constants.js";
import { SECURITY_CHECKS } from "../utils/securityChecksCatalog.js";

/**
 * Strictly static demonstration AWS assessment fixture.
 *
 * - Never calls any backend or AWS API.
 * - Explicitly flagged with `is_demo: true` and never saved to sessionStorage/localStorage.
 * - Demonstrates CRITICAL, WARNING, UNUSED, INFO, HEALTHY, and INCOMPLETE states across
 *   all 10 supported AWS services so visitors can evaluate AWS Clarity before connecting an account.
 */
export function buildDemoScanData() {
  const scannedAt = "2026-11-22T09:30:00Z";

  const resources = {
    ec2_instances: [
      {
        id: "i-0demo9a8b7c6d5e4f",
        name: "prod-web-01",
        type: "ec2_instance",
        service: "EC2",
        status: "WARNING",
        region: "us-east-1",
        issues: [
          {
            rule_id: "EC2-002",
            severity: "WARNING",
            category: "Security Risk",
            title: "EC2 instance does not enforce IMDSv2",
            what_found: "EC2 instance still permits IMDSv1 (HttpTokens is 'optional').",
            why: "Allowing IMDSv1 makes instance IAM role credentials easier to exfiltrate via SSRF vulnerabilities.",
            what_checked: "Inspected EC2 DescribeInstances MetadataOptions.HttpTokens attribute.",
            evidence: { Instance: "i-0demo9a8b7c6d5e4f", HttpTokens: "optional", Expected: "required" },
            fix: "Run `aws ec2 modify-instance-metadata-options --instance-id i-0demo9a8b7c6d5e4f --http-tokens required` or update via EC2 Console → Actions → Instance settings → Modify instance metadata options.",
            verify: "Confirm HttpTokens is 'required' in EC2 instance metadata options, then re-scan in AWS Clarity.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "EC2-001", status: "PASSED" },
            { rule_id: "EC2-002", status: "VIOLATED" },
          ],
        },
        raw: {
          instance_type: "t3.medium",
          state: "running",
          vpc_id: "vpc-0demo11223344",
          subnet_id: "subnet-0demo1122",
          http_tokens: "optional",
          public_ip: "203.0.113.24",
          private_ip: "10.0.1.18",
          ebs_volumes: ["vol-0demo1111aaaa"],
        },
      },
      {
        id: "i-0demo223344556677",
        name: "staging-batch-worker",
        type: "ec2_instance",
        service: "EC2",
        status: "UNUSED",
        region: "eu-west-1",
        issues: [
          {
            rule_id: "EC2-001",
            severity: "UNUSED",
            category: "Potential Cost Waste",
            title: "EC2 instance is stopped",
            what_found: "EC2 instance is in 'stopped' state while retaining attached EBS storage.",
            why: "Stopped instances do not incur EC2 compute charges, but attached EBS volumes continue generating monthly storage charges.",
            what_checked: "Inspected EC2 DescribeInstances instance state.",
            evidence: { Instance: "i-0demo223344556677", InstanceType: "t3.large", State: "stopped", AttachedVolumes: "1" },
            fix: "Confirm whether this staging worker is paused intentionally. Before terminating, take an AMI/EBS snapshot backup if data is needed and verify Terraform/IaC state.",
            verify: "Re-scan in AWS Clarity after restarting or terminating the instance and confirm EC2-001 resolves.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "EC2-001", status: "VIOLATED" },
            { rule_id: "EC2-002", status: "PASSED" },
          ],
        },
        raw: {
          instance_type: "t3.large",
          state: "stopped",
          vpc_id: "vpc-0demo99887766",
          http_tokens: "required",
          ebs_volumes: ["vol-0demo2222bbbb"],
        },
      },
    ],

    elastic_ips: [
      {
        id: "eipalloc-0demo4455",
        name: "198.51.100.77",
        type: "elastic_ip",
        service: "EC2",
        status: "UNUSED",
        region: "us-east-1",
        issues: [
          {
            rule_id: "EIP-001",
            severity: "UNUSED",
            category: "Potential Cost Waste",
            title: "Unassociated Elastic IP incurring hourly IPv4 charges",
            what_found: "Elastic IP address has no active AssociationId.",
            why: "AWS charges hourly for allocated public IPv4 addresses even when unattached to any running resource.",
            what_checked: "Inspected EC2 DescribeAddresses AssociationId field.",
            evidence: { AllocationId: "eipalloc-0demo4455", PublicIp: "198.51.100.77", AssociationId: "None" },
            fix: "Confirm this static IP is not allowlisted by external partners or DNS A-records (releasing permanently forfeits the IP). If unneeded, release via EC2 → Elastic IPs → Release.",
            verify: "Re-scan in AWS Clarity and confirm the Elastic IP no longer appears as unassociated.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [{ rule_id: "EIP-001", status: "VIOLATED" }],
        },
        raw: { public_ip: "198.51.100.77", association_id: null, domain: "vpc" },
      },
    ],

    security_groups: [
      {
        id: "sg-0demo1234567890",
        name: "legacy-ssh-bastion",
        type: "security_group",
        service: "EC2",
        status: "CRITICAL",
        region: "us-east-1",
        issues: [
          {
            rule_id: "SG-002",
            severity: "CRITICAL",
            category: "Security Risk",
            title: "SSH (port 22) open to the internet",
            what_found: "Inbound SSH access is allowed from 0.0.0.0/0 on port 22.",
            why: "Publicly exposed SSH invites continuous brute-force and credential-stuffing attacks.",
            what_checked: "Evaluated Security Group ingress IP permissions for port 22 with unrestricted CIDR sources.",
            evidence: { SecurityGroup: "sg-0demo1234567890", Port: "22", Protocol: "TCP", Source: "0.0.0.0/0" },
            fix: "Edit inbound rules in EC2 → Security Groups to restrict port 22 to your specific IP/VPN CIDR, or remove port 22 and connect privately via AWS Systems Manager Session Manager.",
            verify: "Confirm no inbound rule allows port 22 from 0.0.0.0/0 or ::/0, then re-scan in AWS Clarity.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "SG-001", status: "PASSED" },
            { rule_id: "SG-002", status: "VIOLATED" },
            { rule_id: "SG-003", status: "PASSED" },
            { rule_id: "SG-004", status: "PASSED" },
          ],
        },
        raw: {
          group_name: "legacy-ssh-bastion",
          vpc_id: "vpc-0demo11223344",
          ip_permissions: [{ IpProtocol: "tcp", FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: "0.0.0.0/0" }] }],
        },
      },
    ],

    vpcs: [
      {
        id: "vpc-0demo11223344",
        name: "prod-custom-vpc",
        type: "vpc",
        service: "VPC",
        status: "HEALTHY",
        region: "us-east-1",
        issues: [],
        assessment: {
          status: "COMPLETE",
          checks: [{ rule_id: "VPC-001", status: "PASSED" }],
        },
        raw: { cidr_block: "10.0.0.0/16", is_default: false, state: "available" },
      },
    ],

    internet_gateways: [
      {
        id: "igw-0demo11223344",
        name: "prod-vpc-igw",
        type: "internet_gateway",
        service: "VPC",
        status: "HEALTHY",
        region: "us-east-1",
        issues: [],
        assessment: {
          status: "COMPLETE",
          checks: [{ rule_id: "IGW-001", status: "PASSED" }],
        },
        raw: { attachments: [{ VpcId: "vpc-0demo11223344", State: "available" }] },
      },
    ],

    nat_gateways: [
      {
        id: "nat-0demo99887766",
        name: "prod-nat-az1",
        type: "nat_gateway",
        service: "VPC",
        status: "HEALTHY",
        region: "us-east-1",
        issues: [
          {
            rule_id: "NAT-002",
            severity: "INFO",
            category: "Potential Cost Waste",
            title: "Active NAT Gateway (review ongoing hourly & data charges)",
            what_found: "NAT Gateway is active and incurs ongoing hourly and data-processing charges.",
            why: "NAT Gateways are often required for private subnet egress, but they incur continuous hourly and per-GB charges even with low traffic.",
            what_checked: "Inspected EC2 DescribeNatGateways State and SubnetId.",
            evidence: { NatGateway: "nat-0demo99887766", State: "available", SubnetId: "subnet-0demo1122" },
            fix: "Review private route tables before making changes—deleting an active NAT Gateway breaks private subnet egress. Use free S3/DynamoDB Gateway Endpoints where applicable.",
            verify: "If an unused NAT Gateway is intentionally removed, re-scan in AWS Clarity to confirm.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "NAT-001", status: "PASSED" },
            { rule_id: "NAT-002", status: "REVIEW" },
          ],
        },
        raw: { state: "available", subnet_id: "subnet-0demo1122", vpc_id: "vpc-0demo11223344" },
      },
    ],

    s3_buckets: [
      {
        id: "demo-app-assets-public-2026",
        name: "demo-app-assets-public-2026",
        type: "s3_bucket",
        service: "S3",
        status: "INCOMPLETE",
        region: "us-east-1",
        issues: [
          {
            rule_id: "S3-005",
            severity: "WARNING",
            category: "Security Risk",
            title: "S3 Block Public Access is not fully enabled",
            what_found: "Two of the four S3 Block Public Access controls are disabled.",
            why: "Disabling Block Public Access guardrails leaves the bucket vulnerable to accidental policy or ACL exposure.",
            what_checked: "Queried S3 GetPublicAccessBlock configuration for all 4 flags.",
            evidence: { Bucket: "demo-app-assets-public-2026", DisabledSettings: "BlockPublicPolicy, RestrictPublicBuckets" },
            fix: "Open S3 → Bucket → Permissions → Block public access → Edit and enable all four settings (use CloudFront OAC if serving static web assets).",
            verify: "Re-scan in AWS Clarity and confirm S3-005 passes on this bucket.",
          },
        ],
        assessment: {
          status: "INCOMPLETE",
          checks: [
            { rule_id: "S3-002", status: "CHECK_FAILED", reason: "Could not read bucket policy status: AccessDenied" },
            { rule_id: "S3-003", status: "PASSED" },
            { rule_id: "S3-004", status: "PASSED" },
            { rule_id: "S3-005", status: "VIOLATED" },
          ],
        },
        raw: { name: "demo-app-assets-public-2026", versioning: "Enabled" },
      },
      {
        id: "demo-archive-logs-eu",
        name: "demo-archive-logs-eu",
        type: "s3_bucket",
        service: "S3",
        status: "HEALTHY",
        region: "eu-west-1",
        issues: [],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "S3-002", status: "PASSED" },
            { rule_id: "S3-003", status: "PASSED" },
            { rule_id: "S3-004", status: "PASSED" },
            { rule_id: "S3-005", status: "PASSED" },
          ],
        },
        raw: { name: "demo-archive-logs-eu", versioning: "Enabled" },
      },
    ],

    iam_roles: [
      {
        id: "AROADEMO1234567890",
        name: "AWSClarityReadOnly",
        type: "iam_role",
        service: "IAM",
        status: "HEALTHY",
        region: "global",
        issues: [],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "IAM-001", status: "PASSED" },
            { rule_id: "IAM-002", status: "PASSED" },
            { rule_id: "IAM-003", status: "PASSED" },
            { rule_id: "IAM-004", status: "PASSED" },
            { rule_id: "IAM-005", status: "PASSED" },
            { rule_id: "IAM-006", status: "PASSED" },
            { rule_id: "IAM-007", status: "PASSED" },
            { rule_id: "IAM-008", status: "PASSED" },
          ],
        },
        raw: { role_name: "AWSClarityReadOnly", is_service_linked: false, path: "/" },
      },
    ],

    iam_users: [
      {
        id: "AIDADEMO9876543210",
        name: "ops-deploy-user",
        type: "iam_user",
        service: "IAM",
        status: "CRITICAL",
        region: "global",
        issues: [
          {
            rule_id: "IAM-009",
            severity: "CRITICAL",
            category: "Security Risk",
            title: "IAM user does not have MFA enabled",
            what_found: "IAM user with console sign-in activity has 0 MFA devices registered.",
            why: "Without Multi-Factor Authentication, a single leaked password grants immediate access to your AWS account.",
            what_checked: "Inspected IAM ListUsers PasswordLastUsed and ListMFADevices.",
            evidence: { User: "ops-deploy-user", MFADevices: "0", ConsoleActivity: "2026-11-18T14:12:00Z" },
            fix: "Open IAM → Users → ops-deploy-user → Security credentials → Assign MFA device (hardware key or authenticator app).",
            verify: "Confirm at least one MFA device is active for this user, then re-scan in AWS Clarity.",
          },
          {
            rule_id: "IAM-010",
            severity: "WARNING",
            category: "Security Risk",
            title: "Long-lived active IAM access key (>90 days)",
            what_found: "IAM user has an Active static access key older than 90 days.",
            why: "Key age alone does not mean a key is compromised, but long-lived static credentials carry a larger blast radius if ever leaked.",
            what_checked: "Inspected IAM ListAccessKeys status and CreateDate.",
            evidence: { User: "ops-deploy-user", KeysOver90Days: "AKIADEMOEXAMPLE1 (142d)" },
            fix: "Do NOT delete an active key immediately. Create a replacement key (or migrate to an IAM role), update all dependent applications, deactivate the old key first to confirm nothing breaks, and then delete it.",
            verify: "Re-scan in AWS Clarity after rotating and removing keys older than 90 days.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "IAM-009", status: "VIOLATED" },
            { rule_id: "IAM-010", status: "VIOLATED" },
            { rule_id: "IAM-011", status: "PASSED" },
          ],
        },
        raw: { user_name: "ops-deploy-user", mfa_devices_count: 0 },
      },
    ],

    lambda_functions: [
      {
        id: "demo-invoice-pdf-worker",
        name: "demo-invoice-pdf-worker",
        type: "lambda_function",
        service: "Lambda",
        status: "HEALTHY",
        region: "us-east-1",
        issues: [
          {
            rule_id: "LAM-001",
            severity: "INFO",
            category: "Operational Concern",
            title: "Lambda function unchanged for over 90 days (informational review)",
            what_found: "Function has not been modified in 135 days.",
            why: "A stable function unchanged for >90 days is NOT automatically unhealthy—periodic review simply helps keep dependencies and IAM roles current.",
            what_checked: "Inspected Lambda ListFunctions LastModified timestamp.",
            evidence: { Function: "demo-invoice-pdf-worker", LastModified: "2026-07-10T08:00:00.000+0000", DaysSinceModified: "135" },
            fix: "Check CloudWatch invocation metrics and triggers before making changes; keep active functions intact.",
            verify: "Re-scan in AWS Clarity if you update dependencies or retire a confirmed obsolete function.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "LAM-001", status: "REVIEW" },
            { rule_id: "LAM-002", status: "PASSED" },
          ],
        },
        raw: { runtime: "python3.12", memory_size: 512, timeout: 30, last_modified: "2026-07-10T08:00:00.000+0000" },
      },
    ],

    rds_instances: [
      {
        id: "prod-orders-postgres",
        name: "prod-orders-postgres",
        type: "rds_instance",
        service: "RDS",
        status: "WARNING",
        region: "us-east-1",
        issues: [
          {
            rule_id: "RDS-003",
            severity: "WARNING",
            category: "Operational Concern",
            title: "RDS deletion protection is disabled",
            what_found: "Deletion protection is disabled on this RDS instance.",
            why: "Without deletion protection, a single console click or API call can permanently destroy the database.",
            what_checked: "Inspected RDS DescribeDBInstances DeletionProtection attribute.",
            evidence: { Database: "prod-orders-postgres", Engine: "postgres", DeletionProtection: "Disabled" },
            fix: "Open RDS → Databases → Select DB → Modify → Enable deletion protection → Apply immediately.",
            verify: "Re-scan in AWS Clarity and confirm RDS-003 passes.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "RDS-001", status: "PASSED" },
            { rule_id: "RDS-002", status: "PASSED" },
            { rule_id: "RDS-003", status: "VIOLATED" },
            { rule_id: "RDS-004", status: "PASSED" },
          ],
        },
        raw: { engine: "postgres", publicly_accessible: false, storage_encrypted: true, deletion_protection: false, backup_retention_period: 7 },
      },
    ],

    dynamodb_tables: [
      {
        id: "demo-sessions-table",
        name: "demo-sessions-table",
        type: "dynamodb_table",
        service: "DynamoDB",
        status: "HEALTHY",
        region: "us-east-1",
        issues: [],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "DDB-001", status: "PASSED" },
            { rule_id: "DDB-002", status: "PASSED" },
          ],
        },
        raw: { billing_mode: "PAY_PER_REQUEST", item_count: 1420, sse_description: { Status: "ENABLED", SSEType: "AWS_OWNED" } },
      },
    ],

    ebs_volumes: [
      {
        id: "vol-0demo3333cccc",
        name: "old-migration-disk",
        type: "ebs_volume",
        service: "EBS",
        status: "UNUSED",
        region: "us-east-1",
        issues: [
          {
            rule_id: "EBS-002",
            severity: "UNUSED",
            category: "Potential Cost Waste",
            title: "Unattached EBS volume incurring storage charges",
            what_found: "EBS volume is in 'available' state and not attached to any EC2 instance.",
            why: "Unattached volumes continue billing monthly per provisioned GB even though no EC2 instance is currently using them.",
            what_checked: "Inspected EC2 DescribeVolumes State and Attachments.",
            evidence: { Volume: "vol-0demo3333cccc", State: "available (unattached)", SizeGB: "100", VolumeType: "gp3" },
            fix: "Deleting an EBS volume permanently destroys its data. First check tags/ownership and create an EBS snapshot if data might be needed later, then delete manually from EC2 → Volumes.",
            verify: "Re-scan in AWS Clarity and verify EBS-002 is cleared.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "EBS-001", status: "PASSED" },
            { rule_id: "EBS-002", status: "VIOLATED" },
          ],
        },
        raw: { size: 100, state: "available", encrypted: true, volume_type: "gp3" },
      },
    ],

    snapshots: [
      {
        id: "snap-0demo5555eeee",
        name: "pre-upgrade-db-backup",
        type: "ebs_snapshot",
        service: "EBS",
        status: "HEALTHY",
        region: "us-east-1",
        issues: [
          {
            rule_id: "SNAP-001",
            severity: "INFO",
            category: "Potential Cost Waste",
            title: "EBS snapshot whose original volume no longer exists (review before deleting)",
            what_found: "The original EBS volume for this snapshot no longer exists in the region.",
            why: "Snapshots without their original volume are NOT automatically disposable—many are intentional backups or AMI snapshots, though they incur ongoing snapshot storage charges.",
            what_checked: "Cross-referenced Snapshot VolumeId against active EBS volumes in the region.",
            evidence: { Snapshot: "snap-0demo5555eeee", SourceVolumeId: "vol-0deleted9999", VolumeSizeGB: "80" },
            fix: "Confirm this snapshot is not backing an active AMI or retention policy (deletion is permanent). Delete manually in EC2 → Snapshots only if confirmed obsolete.",
            verify: "After reviewing or removing obsolete snapshots, re-scan in AWS Clarity to confirm.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [{ rule_id: "SNAP-001", status: "REVIEW" }],
        },
        raw: { volume_id: "vol-0deleted9999", volume_size: 80, encrypted: true },
      },
    ],

    cloudwatch_alarms: [
      {
        id: "demo-dead-letter-queue-alarm",
        name: "demo-dead-letter-queue-alarm",
        type: "cloudwatch_alarm",
        service: "CloudWatch",
        status: "HEALTHY",
        region: "us-east-1",
        issues: [
          {
            rule_id: "CW-002",
            severity: "INFO",
            category: "Operational Concern",
            title: "CloudWatch alarm currently in INSUFFICIENT_DATA state (review metric)",
            what_found: "CloudWatch alarm state is currently INSUFFICIENT_DATA.",
            why: "INSUFFICIENT_DATA is NOT automatically a failure—it is common for sparse/event-driven metrics such as dead-letter queues.",
            what_checked: "Inspected CloudWatch DescribeAlarms StateValue attribute.",
            evidence: { Alarm: "demo-dead-letter-queue-alarm", StateValue: "INSUFFICIENT_DATA" },
            fix: "Inspect the alarm metric and 'Missing data treatment' setting in CloudWatch. Keep alarms monitoring sparse workloads; delete only if the monitored resource no longer exists.",
            verify: "Re-scan in AWS Clarity if you update or remove a confirmed orphaned alarm.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "CW-001", status: "PASSED" },
            { rule_id: "CW-002", status: "REVIEW" },
          ],
        },
        raw: { actions_enabled: true, state_value: "INSUFFICIENT_DATA" },
      },
    ],

    cloudwatch_log_groups: [
      {
        id: "/aws/lambda/demo-api-handler",
        name: "/aws/lambda/demo-api-handler",
        type: "cloudwatch_log_group",
        service: "CloudWatch",
        status: "WARNING",
        region: "us-east-1",
        issues: [
          {
            rule_id: "CW-003",
            severity: "WARNING",
            category: "Potential Cost Waste",
            title: "CloudWatch Log Group has no retention policy (Never Expire)",
            what_found: "CloudWatch Log Group has no retention period configured (Never Expire).",
            why: "Log groups without a retention policy store logs forever, causing CloudWatch storage charges to grow steadily over time.",
            what_checked: "Inspected CloudWatch Logs DescribeLogGroups retentionInDays and storedBytes.",
            evidence: { LogGroup: "/aws/lambda/demo-api-handler", Retention: "Never Expire", StoredMB: "482.5 MB" },
            fix: "Open CloudWatch → Log groups → Select Log Group → Actions → Edit retention setting (e.g., 14, 30, or 90 days).",
            verify: "Confirm a retention period is shown on the log group, then re-scan in AWS Clarity.",
          },
        ],
        assessment: {
          status: "COMPLETE",
          checks: [{ rule_id: "CW-003", status: "VIOLATED" }],
        },
        raw: { retention_in_days: null, stored_bytes: 505937920 },
      },
    ],

    cloudtrail_trails: [
      {
        id: "arn:aws:cloudtrail:us-east-1:000000000000:trail/demo-org-audit",
        name: "demo-org-audit",
        type: "cloudtrail_trail",
        service: "CloudTrail",
        status: "HEALTHY",
        region: "us-east-1",
        issues: [],
        assessment: {
          status: "COMPLETE",
          checks: [
            { rule_id: "CT-001", status: "PASSED" },
            { rule_id: "CT-002", status: "PASSED" },
            { rule_id: "CT-003", status: "PASSED" },
          ],
        },
        raw: { home_region: "us-east-1", is_logging: true, is_multi_region_trail: true, log_file_validation_enabled: true },
      },
    ],
  };

  const failures = [
    {
      service: "S3",
      label: "demo-app-assets-public-2026 (S3-002)",
      region: "us-east-1",
      reason: "Could not read bucket policy status: AccessDenied (demonstrating how missing permissions are surfaced honestly instead of hidden)",
      required_permission: "s3:GetBucketPolicyStatus",
    },
    {
      service: "EC2",
      label: "EC2 Instances",
      region: "me-south-1",
      reason: "AWS regional endpoint ec2.me-south-1.amazonaws.com unreachable (demonstrating inaccessible-region transparency)",
      required_permission: "ec2:DescribeInstances",
    },
  ];

  const serviceSummary = SERVICE_COVERAGE_MATRIX.map((entry) => {
    const keys = {
      EC2: ["ec2_instances", "elastic_ips", "security_groups"],
      VPC: ["vpcs", "internet_gateways", "nat_gateways"],
      S3: ["s3_buckets"],
      IAM: ["iam_roles", "iam_users"],
      Lambda: ["lambda_functions"],
      RDS: ["rds_instances"],
      DynamoDB: ["dynamodb_tables"],
      EBS: ["ebs_volumes", "snapshots"],
      CloudWatch: ["cloudwatch_alarms", "cloudwatch_log_groups"],
      CloudTrail: ["cloudtrail_trails"],
    }[entry.service] || [];
    const resourceCount = keys.reduce((acc, k) => acc + (resources[k]?.length || 0), 0);
    const svcFailures = failures.filter((f) => f.service === entry.service);
    return {
      service: entry.service,
      scope: entry.scope,
      status: svcFailures.length > 0 ? "INCOMPLETE" : "COMPLETE",
      resource_count: resourceCount,
      failure_count: svcFailures.length,
      resource_types: entry.resources.map((label) => ({ label })),
    };
  });

  const allItems = Object.values(resources).flat();

  return {
    is_demo: true,
    status: "INCOMPLETE",
    scan_state: "INCOMPLETE",
    account_id: "000000000000",
    caller_arn: "arn:aws:sts::000000000000:assumed-role/AWSClarityDemoReadOnly/DemoSession",
    region: "all-enabled-regions",
    regions: ["us-east-1", "eu-west-1", "ap-southeast-1", "me-south-1"],
    scanned_at: scannedAt,
    scan_duration_ms: 2480,
    partial: true,
    account_advisories: [],
    summary: {
      total_resources: allItems.length,
      critical_issues: allItems.filter((r) => r.status === "CRITICAL").length,
      warnings: allItems.filter((r) => r.status === "WARNING").length,
      unused: allItems.filter((r) => r.status === "UNUSED").length,
      healthy: allItems.filter((r) => r.status === "HEALTHY").length,
      incomplete_resources: allItems.filter((r) => r.status === "INCOMPLETE").length,
      health_score_available: false,
    },
    coverage: {
      status: "INCOMPLETE",
      is_partial: true,
      region_discovery: { mode: "demo_fixture", status: "COMPLETE", count: 4 },
      regions_scanned: ["us-east-1", "eu-west-1", "ap-southeast-1", "me-south-1"],
      regions_succeeded: ["us-east-1", "eu-west-1", "ap-southeast-1"],
      regions_failed: ["me-south-1"],
      services_supported: SERVICE_COVERAGE_MATRIX.map((s) => s.service),
      services_scanned: SERVICE_COVERAGE_MATRIX.map((s) => s.service),
      services_complete: serviceSummary.filter((s) => s.status === "COMPLETE").map((s) => s.service),
      service_summary: serviceSummary,
      resources_inspected: allItems.length,
      findings_detected: allItems.reduce((acc, r) => acc + (r.issues?.length || 0), 0),
      failures,
      unsupported_services: [
        { service: "AWS Cost Explorer & Billing APIs", reason: "Deliberately excluded to avoid paid API requests ($0.01/request)." },
        { service: "Paid AWS Security Services (GuardDuty / Config / Security Hub)", reason: "Excluded so scanning never triggers paid AWS services." },
        { service: "Other AWS Services Beyond the 10 Supported v1 Services", reason: "v1 intentionally focuses on 10 core services for accurate, transparent coverage." },
        { service: "Customer Data Contents", reason: "AWS Clarity never reads S3 object contents, RDS/DynamoDB rows, Lambda source code, or CloudWatch log events." },
      ],
      rules_catalog: SECURITY_CHECKS,
    },
    resources,
  };
}
