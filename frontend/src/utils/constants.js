export const RESOURCE_TYPE_LABELS = {
  ec2_instance: "EC2 Instance",
  s3_bucket: "S3 Bucket",
  rds_instance: "RDS Instance",
  ebs_volume: "EBS Volume",
  elastic_ip: "Elastic IP",
  security_group: "Security Group",
  ebs_snapshot: "EBS Snapshot",
  iam_role: "IAM Role",
  iam_user: "IAM User",
  iam_policy: "IAM Policy",
  lambda_function: "Lambda Function",
  nat_gateway: "NAT Gateway",
  load_balancer: "Load Balancer",
  dynamodb_table: "DynamoDB Table",
  vpc: "VPC",
  subnet: "Subnet",
  route_table: "Route Table",
  internet_gateway: "Internet Gateway",
  cloudfront_distribution: "CloudFront Distribution",
  route53_hosted_zone: "Route 53 Hosted Zone",
  route53_record: "Route 53 Record",
};

export const STATUS_BADGE = {
  CRITICAL:     "bg-red-500/20 text-red-400 border-red-500/30",
  WARNING:      "bg-amber-500/20 text-amber-400 border-amber-500/30",
  HEALTHY:      "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  ORPHANED:     "bg-slate-500/20 text-slate-400 border-slate-500/30",
  NOT_ASSESSED: "bg-slate-700/30 text-slate-400 border-slate-600/30",
};

// Shared text-color classes for status values (used in comparison panels, drawers, etc.)
export const STATUS_COLOR = {
  CRITICAL:     "text-red-400",
  WARNING:      "text-amber-400",
  HEALTHY:      "text-emerald-400",
  ORPHANED:     "text-slate-400",
  NOT_ASSESSED: "text-slate-500",
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

