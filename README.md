# AWS Clarity 🔍

AWS Clarity is a serverless, read-only cloud security posture management (CSPM) tool designed to scan an AWS account for common misconfigurations, exposed resources, and orphaned infrastructure. It evaluates resources like S3, EC2, RDS, IAM, and Security Groups against security best practices and provides a clean, client-side rendered React dashboard to visualize the results.

## Overview

### Key Capabilities
- **Read-Only Scanning:** Employs an exactingly scoped IAM role using `sts:AssumeRole` to ensure strict, read-only access—no modifications are ever made to the target environment.
- **Client-Side Filtering:** The React dashboard handles all sorting and filtering logic locally, providing instant visual feedback.
- **Robust Rule Engine:** Automatically discovers critical vulnerabilities (e.g., publicly accessible S3 buckets, `0.0.0.0/0` SSH access) and identifies orphaned resources (e.g., unattached EBS volumes, unassociated Elastic IPs) to help cut down costs.
- **Timeout Protection:** If account resources are too expansive, the backend enforces a hard 55-second Lambda timeout, gracefully cutting off the scan and returning partial results without crashing.

## Architecture

The architecture utilizes a fully serverless, highly scalable AWS stack provisioned entirely via Terraform.

```text
       Target AWS Account                  AWS Clarity Infrastructure (Deployment Account)
  +--------------------------+        +-------------------------------------------------+
  |                          |        |                                                 |
  |  [IAM ReadOnly Role] <---+-- STS -+-- [AWS Lambda (Python)]                         |
  |                          |        |           ^                                     |
  +--------------------------+        |           |                                     |
                                      |     [API Gateway]                               |
                                      |           ^                                     |
                                      |           | HTTPS POST /scan                    |
                                      |           |                                     |
                                      |   [React Frontend App]                          |
                                      |    (hosted via S3)                              |
                                      |           ^                                     |
                                      |           | HTTPS                               |
                                      |     [CloudFront]                                |
                                      +-----------|-------------------------------------+
                                                  |
                                             End User
```

## Deployment Instructions

### Prerequisites
- AWS CLI configured with appropriate permissions.
- Terraform installed.
- Node.js & npm installed to build the frontend.

### 1. Provision Backend Infrastructure
Deploy the IAM roles, Lambda function, API Gateway, S3 hosting bucket, and CloudFront distribution using Terraform:
```bash
cd infra
terraform init
terraform apply
```
After successfully applying, Terraform will output the `api_gateway_url`, `cloudfront_url`, and `s3_bucket_name`.

### 2. Configure and Build Frontend
Set the API Gateway URL in your frontend environment:
```bash
cd ../frontend
echo "VITE_API_URL=<your-api-gateway-url>" > .env
npm install
npm run build
```

### 3. Deploy Frontend Assets
Sync the compiled application to your S3 bucket and invalidate the CloudFront cache (replace `<bucket>` and `<id>` with your Terraform outputs):
```bash
aws s3 sync dist/ s3://<bucket-name>/ --delete
aws cloudfront create-invalidation --distribution-id <id> --paths "/*"
```
The application will now be live at your CloudFront URL!

## Usage Guide (Target Account)

To scan an account, you must create an IAM Role in the **target account** that trusts the AWS Clarity Lambda role.

1. Go to IAM → Roles → Create Role in the target account.
2. Select "Another AWS Account" and enter the AWS Account ID where AWS Clarity is deployed.
3. Require an External ID and set it to: `aws-clarity-scan`.
4. Attach a custom inline policy containing standard `Describe` and `List` permissions:
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
        "s3:ListBucket",
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
5. Copy the ARN of the resulting role and paste it into the AWS Clarity web interface.

## Teardown

To destroy the deployment and remove all AWS Clarity infrastructure from your deployment account, navigate to the `infra` directory and execute:
```bash
terraform destroy
```
*(Note: You may need to manually empty the S3 bucket if `force_destroy` is not enabled before Terraform can securely delete it.)*
