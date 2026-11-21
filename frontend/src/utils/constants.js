export const RESOURCE_COLLECTION_KEYS = [
  "ec2_instances",
  "ebs_volumes",
  "snapshots",
  "elastic_ips",
  "security_groups",
  "vpcs",
  "internet_gateways",
  "nat_gateways",
  "load_balancers",
  "s3_buckets",
  "rds_instances",
  "dynamodb_tables",
  "lambda_functions",
  "iam_roles",
];

export const RESOURCE_TYPE_LABELS = {
  ec2_instance: "EC2 Instance",
  ebs_volume: "EBS Volume",
  ebs_snapshot: "EBS Snapshot",
  elastic_ip: "Elastic IP",
  security_group: "Security Group",
  vpc: "VPC",
  internet_gateway: "Internet Gateway",
  nat_gateway: "NAT Gateway",
  load_balancer: "Load Balancer",
  s3_bucket: "S3 Bucket",
  rds_instance: "RDS Database",
  dynamodb_table: "DynamoDB Table",
  lambda_function: "Lambda Function",
  iam_role: "IAM Role",
};

export const RESOURCE_SERVICE_MAP = {
  ec2_instance: "EC2",
  ebs_volume: "EC2",
  ebs_snapshot: "EC2",
  elastic_ip: "EC2",
  security_group: "EC2",
  vpc: "VPC",
  internet_gateway: "VPC",
  nat_gateway: "VPC",
  load_balancer: "ELB",
  s3_bucket: "S3",
  rds_instance: "RDS",
  dynamodb_table: "DynamoDB",
  lambda_function: "Lambda",
  iam_role: "IAM",
};

export const SUPPORTED_SERVICES_OVERVIEW = [
  {
    service: "EC2 & EBS",
    resources: "Instances, Volumes, Snapshots, Elastic IPs, Security Groups",
    focus: "Open SSH/RDP/DB ports, IMDSv2, unencrypted disks, stopped instances, unattached volumes, orphan snapshots & idle Elastic IPs",
  },
  {
    service: "VPC & ELB",
    resources: "VPCs, Internet Gateways, NAT Gateways, Load Balancers",
    focus: "Active NAT Gateway billing risk, default VPCs, unattached IGWs, public & legacy Classic load balancers",
  },
  {
    service: "S3",
    resources: "S3 Buckets (filtered by selected region)",
    focus: "Public policies, public ACLs, Block Public Access controls, default encryption & empty buckets",
  },
  {
    service: "RDS",
    resources: "RDS DB Instances",
    focus: "Publicly accessible databases, encryption at rest, deletion protection & automated backups",
  },
  {
    service: "DynamoDB",
    resources: "DynamoDB Tables",
    focus: "Encryption status & empty provisioned-capacity tables",
  },
  {
    service: "Lambda",
    resources: "Lambda Functions",
    focus: "Deprecated runtimes & functions untouched for over 90 days",
  },
  {
    service: "IAM",
    resources: "IAM Roles (global)",
    focus: "Wildcard actions/resources, AdministratorAccess, public trust policies & missing cross-account ExternalId",
  },
];

// Single source of truth for the exact 25 least-privilege read-only IAM actions
// required by AWS Clarity (matches infra/iam.tf and backend scanners 1:1).
export const IAM_POLICY_JSON = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeAddresses",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeNatGateways",
        "ec2:DescribeInternetGateways",
        "elasticloadbalancing:DescribeLoadBalancers",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "rds:DescribeDBInstances",
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "lambda:ListFunctions",
        "iam:ListRoles",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    }
  ]
}`;

export const DEFAULT_EXTERNAL_ID = "aws-clarity-scan";

export const STATUS_BADGE = {
  CRITICAL:     "bg-red-500/15 text-red-400 border-red-500/30",
  WARNING:      "bg-amber-500/15 text-amber-400 border-amber-500/30",
  HEALTHY:      "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  ORPHANED:     "bg-sky-500/15 text-sky-300 border-sky-500/30",
  NOT_ASSESSED: "bg-slate-700/30 text-slate-400 border-slate-600/40",
};

export const STATUS_COLOR = {
  CRITICAL:     "text-red-400",
  WARNING:      "text-amber-400",
  HEALTHY:      "text-emerald-400",
  ORPHANED:     "text-sky-300",
  NOT_ASSESSED: "text-slate-400",
};

export const CATEGORY_BADGE = {
  Security:    "bg-rose-500/10 text-rose-300 border-rose-500/20",
  "Cost Risk": "bg-amber-500/10 text-amber-300 border-amber-500/20",
  Unused:      "bg-sky-500/10 text-sky-300 border-sky-500/20",
  Reliability: "bg-indigo-500/10 text-indigo-300 border-indigo-500/20",
  Hygiene:     "bg-slate-500/15 text-slate-300 border-slate-500/25",
};

export const SUPPORTED_REGIONS = [
  { id: "us-east-1",      label: "US East (N. Virginia)" },
  { id: "us-east-2",      label: "US East (Ohio)" },
  { id: "us-west-1",      label: "US West (N. California)" },
  { id: "us-west-2",      label: "US West (Oregon)" },
  { id: "eu-west-1",      label: "Europe (Ireland)" },
  { id: "eu-west-2",      label: "Europe (London)" },
  { id: "eu-central-1",   label: "Europe (Frankfurt)" },
  { id: "ap-southeast-1", label: "Asia Pacific (Singapore)" },
  { id: "ap-southeast-2", label: "Asia Pacific (Sydney)" },
  { id: "ap-northeast-1", label: "Asia Pacific (Tokyo)" },
  { id: "ca-central-1",   label: "Canada (Central)" },
  { id: "sa-east-1",      label: "South America (São Paulo)" },
];
