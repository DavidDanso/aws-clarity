# Customer IAM Permissions (Strictly Read-Only)

AWS Clarity uses **28 read-only IAM actions by default** (9 zero-request-charge services) or **34 actions** if you explicitly opt into S3 bucket configuration checks (`--include-s3-checks`).

- **No cross-account trust to AWS Clarity:** Attach this policy to your own IAM Identity Center permission set or existing read-only IAM role.
- **Zero write, modify, stop, delete, or data-read actions:** Never requests `s3:GetObject`, `s3:ListBucket`, `dynamodb:Scan`/`GetItem`, `logs:GetLogEvents`, `lambda:GetFunction`, `ce:*`, `guardduty:*`, `config:*`, or `securityhub:*`.

## Action-by-Action Reference

| Service | Actions | Purpose | Customer-Side API Cost |
| --- | --- | --- | --- |
| **STS / EC2 (Discovery)** | `sts:GetCallerIdentity`, `ec2:DescribeRegions` | Verify active AWS account locally & list enabled regions | Free control-plane APIs |
| **EC2** | `ec2:DescribeInstances`, `ec2:DescribeAddresses`, `ec2:DescribeSecurityGroups` | Inspect instance state, IMDSv2, Elastic IPs, and firewall ingress rules | Free control-plane APIs |
| **VPC** | `ec2:DescribeVpcs`, `ec2:DescribeInternetGateways`, `ec2:DescribeNatGateways` | Inspect default VPC exposure, unattached IGWs, and NAT Gateways | Free control-plane APIs |
| **EBS** | `ec2:DescribeVolumes`, `ec2:DescribeSnapshots` | Inspect volume encryption, unattached volumes, and self-owned snapshots | Free control-plane APIs |
| **IAM** | `iam:ListRoles`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:ListUsers`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy` | Inspect role/user policies, trusts, MFA status, and access key creation dates (never reads passwords or secret keys) | Free (AWS IAM has no API request charge) |
| **Lambda** | `lambda:ListFunctions` | Inspect runtimes and `LastModified` dates (never downloads code) | Free control-plane API |
| **RDS** | `rds:DescribeDBInstances` | Inspect public access, encryption, deletion protection, and backup retention | Free control-plane API |
| **DynamoDB** | `dynamodb:ListTables`, `dynamodb:DescribeTable` | Inspect encryption and empty provisioned tables (never reads items) | Free control-plane APIs |
| **CloudWatch** | `cloudwatch:DescribeAlarms`, `logs:DescribeLogGroups` | Inspect alarm state/actions and Log Group retention (never calls `GetMetricData` or reads logs) | Free control-plane APIs |
| **CloudTrail** | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` | Inspect multi-region coverage, log validation, and active logging | Free control-plane APIs |
| **S3 (Optional Opt-In)** | `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetEncryptionConfiguration`, `s3:GetBucketPublicAccessBlock` | Inspect bucket public policy, ACL, Block Public Access, and encryption config (**no `s3:ListBucket` or `s3:GetObject`**) | **Optional (`--include-s3-checks`):** S3 LIST (\$0.005/1,000) & GET (\$0.0004/1,000) outside 12-month S3 Free Tier |

## Generating the Exact Policy JSON via CLI

```bash
# 28 zero-request-charge actions (default scan)
aws-clarity policy --zero-cost-only --output aws-clarity-policy-default.json

# 34 actions (including optional S3 metadata checks)
aws-clarity policy --output aws-clarity-policy-with-s3.json
```
