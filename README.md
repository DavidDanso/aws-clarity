# AWS Clarity

AWS Clarity is a serverless, read-only AWS resource scanner that provides a rapid, high-level overview of the security state of an AWS account. It performs read-only scans across various crucial AWS resources (S3, EC2, RDS, EBS, IAM, and Security Groups), analyzing configuration rules and rapidly highlighting misconfigurations or orphaned infrastructure in a visually compelling dashboard.

## What the App Does
- **Scans Key AWS Services:** Reads S3 buckets, EC2 instances, EBS volumes & snapshots, RDS instances, Elastic IPs, Security Groups, and IAM Roles.
- **Identifies Security Risks:** Flags wildcards (`*`) in IAM policies, public-facing EC2 or RDS instances, open SSH rules, and unencrypted databases/volumes.
- **Highlights Orphaned Infrastructure:** Identifies suspended EC2s, unused Elastic IPs, dangling EBS volumes, and obsolete snapshots to save you money.
- **Actionable Remediation:** Each issue provides an explicit `Fix` instruction directly inside the frontend detail drawer.
- **Time-Bound Scanning:** Lambda runs contain a `partial: true` fail-safe that guarantees UI delivery even if massive AWS accounts time out the scanner. 

## Architecture

```text
       ┌───────────┐         ┌───────────┐         ┌──────────────────┐
       │           │         │           │         │                  │
User ──┤  Browser  ├─────────►  Route53  ├─────────►  S3 Static Site  │
       │ (React)   │         │ CloudFront│         │ (AWS Clarity UI) │
       └─────┬─────┘         └───────────┘         └──────────────────┘
             │                                              
             │ REST POST /scan
             ▼                                              
       ┌───────────┐         ┌───────────┐         ┌───────────────────┐
       │           │         │           │         │                   │
       │ API Gate  ├─────────► Lambda    ├────┬────► sts:AssumeRole    │
       │ (REST)    │         │ (Python)  │    │    │ (Target Account)  │
       └───────────┘         └───────────┘    │    └───────────────────┘
                                              │      
                                              │    ┌───────────────────┐
                                              │    │ AWS APIs:         │
                                              ├────► EC2, S3, RDS, EBS │
                                              │    │ IAM, Security Grps│
                                              │    └───────────────────┘
```

## How to Create the Target IAM Role
The AWS Clarity backend relies on cross-account trust via `sts:AssumeRole`. 

1. Go to **AWS IAM** -> **Roles** -> **Create Role**.
2. Select **AWS account** (Another AWS account) and input your designated deployment account ID.
3. Check the box to require an **External ID** and utilize `aws-clarity-scan`.
4. Create an inline policy with the following exact statement:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "ec2:DescribeInstances",
                   "ec2:DescribeVolumes",
                   "ec2:DescribeSnapshots",
                   "ec2:DescribeAddresses",
                   "ec2:DescribeSecurityGroups",
                   "s3:ListAllMyBuckets",
                   "s3:GetBucketLocation",
                   "s3:GetBucketPolicyStatus",
                   "s3:GetBucketAcl",
                   "s3:GetBucketEncryption",
                   "s3:GetPublicAccessBlock",
                   "rds:DescribeDBInstances",
                   "iam:ListRoles",
                   "iam:ListRolePolicies",
                   "iam:GetRolePolicy"
               ],
               "Resource": "*"
           }
       ]
   }
   ```
5. Note the resulting Role ARN (`arn:aws:iam::[id]:role/[name]`). Paste this directly into the AWS Clarity web dashboard.

## Deployment Steps

1. **Deploy the Infrastructure**
   ```bash
   cd infra
   terraform init
   terraform apply
   ```
2. **Retrieve Terraform Outputs**
   Note down your `s3_bucket_name` and `cloudfront_url`. Wait briefly for API Gateway & Lambda to finish propagating.
3. **Build the Frontend**
   ```bash
   cd frontend
   npm install
   npm run build
   ```
4. **Deploy Assets to S3**
   Upload the compiled React artifacts locally using AWS CLI.
   ```bash
   aws s3 sync dist/ s3://<s3_bucket_name_from_tf_output>/ --delete
   ```
5. **Invalidate Edge Caches**
   Guarantee your CloudFront distribution serves the fresh code.
   ```bash
   aws cloudfront create-invalidation --distribution-id <distribution_id> --paths "/*"
   ```
6. Navigate to your `cloudfront_url` via a Web Browser!

## Tear Down

Since the entire backend and hosting layer is strictly managed by Terraform, destroying AWS Clarity involves zero manual cleanup across AWS Services.

To securely obliterate the scanner's infrastructure:
```bash
cd infra
# Warning: Completely unprovisions all lambdas, buckets, logic distributions
terraform destroy
```
