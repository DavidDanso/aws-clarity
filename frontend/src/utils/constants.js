export const SUPPORTED_SERVICES = [
  "EC2",
  "VPC",
  "S3",
  "IAM",
  "Lambda",
  "RDS",
  "DynamoDB",
  "EBS",
  "CloudWatch",
  "CloudTrail",
];

export const RESOURCE_COLLECTION_KEYS = [
  "ec2_instances",
  "elastic_ips",
  "security_groups",
  "vpcs",
  "internet_gateways",
  "nat_gateways",
  "s3_buckets",
  "iam_roles",
  "iam_users",
  "lambda_functions",
  "rds_instances",
  "dynamodb_tables",
  "ebs_volumes",
  "snapshots",
  "cloudwatch_alarms",
  "cloudwatch_log_groups",
  "cloudtrail_trails",
];

export const RESOURCE_TYPE_LABELS = {
  ec2_instance: "EC2 Instance",
  elastic_ip: "Elastic IP",
  security_group: "Security Group",
  vpc: "VPC",
  internet_gateway: "Internet Gateway",
  nat_gateway: "NAT Gateway",
  s3_bucket: "S3 Bucket",
  iam_role: "IAM Role",
  iam_user: "IAM User",
  lambda_function: "Lambda Function",
  rds_instance: "RDS Database",
  dynamodb_table: "DynamoDB Table",
  ebs_volume: "EBS Volume",
  ebs_snapshot: "EBS Snapshot",
  cloudwatch_alarm: "CloudWatch Alarm",
  cloudwatch_log_group: "CloudWatch Log Group",
  cloudtrail_trail: "CloudTrail Trail",
};

export const RESOURCE_SERVICE_MAP = {
  ec2_instance: "EC2",
  elastic_ip: "EC2",
  security_group: "EC2",
  vpc: "VPC",
  internet_gateway: "VPC",
  nat_gateway: "VPC",
  s3_bucket: "S3",
  iam_role: "IAM",
  iam_user: "IAM",
  lambda_function: "Lambda",
  rds_instance: "RDS",
  dynamodb_table: "DynamoDB",
  ebs_volume: "EBS",
  ebs_snapshot: "EBS",
  cloudwatch_alarm: "CloudWatch",
  cloudwatch_log_group: "CloudWatch",
  cloudtrail_trail: "CloudTrail",
};

export const SERVICE_COVERAGE_MATRIX = [
  {
    service: "EC2",
    scope: "All enabled regions",
    resources: ["EC2 Instances", "Elastic IPs", "Security Groups"],
    checks: "Open all-traffic / SSH / RDP / database ports, IMDSv2 enforcement, stopped instances & idle Elastic IPs",
  },
  {
    service: "VPC",
    scope: "All enabled regions",
    resources: ["VPCs", "Internet Gateways", "NAT Gateways"],
    checks: "Public workloads in default VPC, unattached Internet Gateways, failed & bill-generating active NAT Gateways",
  },
  {
    service: "S3",
    scope: "Global (with bucket region)",
    resources: ["S3 Buckets"],
    checks: "Public bucket policies, public ACLs, Block Public Access controls, encryption verification & empty buckets",
  },
  {
    service: "IAM",
    scope: "Global",
    resources: ["IAM Roles", "IAM Users"],
    checks: "Context-aware wildcard policies, admin managed policies, public & cross-account trust policies, user MFA & stale access keys",
  },
  {
    service: "Lambda",
    scope: "All enabled regions",
    resources: ["Lambda Functions"],
    checks: "Deprecated runtimes & functions untouched for over 90 days",
  },
  {
    service: "RDS",
    scope: "All enabled regions",
    resources: ["RDS DB Instances"],
    checks: "Publicly accessible databases, encryption at rest, deletion protection & automated backup retention",
  },
  {
    service: "DynamoDB",
    scope: "All enabled regions",
    resources: ["DynamoDB Tables"],
    checks: "Encryption status (respecting AWS-owned default encryption) & empty provisioned-capacity tables",
  },
  {
    service: "EBS",
    scope: "All enabled regions",
    resources: ["EBS Volumes", "EBS Snapshots"],
    checks: "Unencrypted volumes, unattached volumes & orphaned snapshots from deleted volumes",
  },
  {
    service: "CloudWatch",
    scope: "All enabled regions",
    resources: ["CloudWatch Alarms", "CloudWatch Log Groups"],
    checks: "Disabled alarm actions, INSUFFICIENT_DATA alarms & Log Groups set to Never Expire",
  },
  {
    service: "CloudTrail",
    scope: "Home-region deduplicated",
    resources: ["CloudTrail Trails"],
    checks: "Active logging status, multi-region coverage, log file integrity validation & missing account trail advisory",
  },
];

// Exact 36 least-privilege read-only IAM actions for the 10 supported AWS services (matches infra/iam.tf 1:1).
export const IAM_POLICY_JSON = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions",
        "ec2:DescribeInstances",
        "ec2:DescribeAddresses",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "iam:ListRoles",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "lambda:ListFunctions",
        "rds:DescribeDBInstances",
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "cloudwatch:DescribeAlarms",
        "logs:DescribeLogGroups",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    }
  ]
}`;

export const STATUS_BADGE = {
  CRITICAL:   "bg-red-500/15 text-red-400 border-red-500/30",
  WARNING:    "bg-amber-500/15 text-amber-400 border-amber-500/30",
  UNUSED:     "bg-sky-500/15 text-sky-300 border-sky-500/30",
  HEALTHY:    "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  INCOMPLETE: "bg-orange-500/15 text-orange-300 border-orange-500/30",
};

export const STATUS_COLOR = {
  CRITICAL:   "text-red-400",
  WARNING:    "text-amber-400",
  UNUSED:     "text-sky-300",
  HEALTHY:    "text-emerald-400",
  INCOMPLETE: "text-orange-300",
};

export const CATEGORY_BADGE = {
  Security:    "bg-rose-500/10 text-rose-300 border-rose-500/20",
  "Cost Risk": "bg-amber-500/10 text-amber-300 border-amber-500/20",
  Unused:      "bg-sky-500/10 text-sky-300 border-sky-500/20",
  Reliability: "bg-indigo-500/10 text-indigo-300 border-indigo-500/20",
  Hygiene:     "bg-slate-500/15 text-slate-300 border-slate-500/25",
};
