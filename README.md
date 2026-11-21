# AWS Clarity

**AWS Clarity** is a secure, read-only AWS account visibility platform. Connect an AWS account using an IAM Role ARN and External ID to view, search, and understand your AWS resources across commonly used services—spotting security misconfigurations, unused resources, and common sources of unexpected AWS spending from one clean dashboard.

---

## Core Principles

- **Strictly Read-Only:** Requests exactly 25 least-privilege `Describe*`, `List*`, and `Get*` actions. Never creates, modifies, stops, or deletes customer resources.
- **Security First:** Temporary 1-hour AWS STS credentials (`sts:AssumeRole`), per-account `sts:ExternalId` confused-deputy protection, 122-bit random scan IDs, compressed encrypted DynamoDB cache with 1-hour automatic TTL deletion, and zero credential storage.
- **Deterministic Findings:** 37 deterministic rules evaluate configuration directly from AWS API responses, producing explainable findings (`What We Found`, `Why It Matters`, `Observed Evidence`, `Recommended Fix`) and explicit `NOT_ASSESSED` / `PARTIAL` disclosures when evidence or permissions are missing.
- **Focused Scope:** Deliberately covers the 7 most commonly used AWS service families (14 resource types) so scans remain fast, accurate, and transparent.
- **Zero-Cost Priority:** Makes **zero** paid AWS API calls (no Cost Explorer, GuardDuty, AWS Config, or Security Hub) and runs on AWS Free Tier–friendly serverless infrastructure (CloudFront + private S3, API Gateway, 512MB Lambda with 14-day CloudWatch log retention, and on-demand DynamoDB with 1-hour TTL).

---

## Supported AWS Services (v1 Scope)

| Service Family | Resource Types Inspected | Key Security & Cost-Risk Checks |
| :--- | :--- | :--- |
| **EC2 & EBS** | EC2 Instances, EBS Volumes, EBS Snapshots, Elastic IPs, Security Groups | Open all-traffic/SSH/RDP/database ports (`SG-001`–`SG-004`), IMDSv2 enforcement (`EC2-002`), stopped instances (`EC2-001`), unencrypted & unattached EBS (`EBS-001`–`EBS-002`), orphaned snapshots (`SNAP-001`), idle Elastic IPs (`EIP-001`) |
| **VPC & ELB** | VPCs, Internet Gateways, NAT Gateways, Load Balancers (ALB/NLB/Classic) | Default VPCs (`VPC-001`), unattached IGWs (`IGW-001`), failed & bill-generating active NAT Gateways (`NAT-001`–`NAT-002`), internet-facing & legacy Classic load balancers (`ELB-001`–`ELB-002`) |
| **S3** | S3 Buckets (filtered to selected region) | Public bucket policies (`S3-002`), public ACLs (`S3-003`), Block Public Access controls (`S3-005`), encryption verification (`S3-004`), empty buckets (`S3-001`) |
| **RDS** | RDS DB Instances | Publicly accessible databases (`RDS-001`), unencrypted storage (`RDS-002`), deletion protection (`RDS-003`), automated backups disabled (`RDS-004`) |
| **DynamoDB** | DynamoDB Tables | Encryption status (`DDB-001`), empty provisioned-capacity tables (`DDB-002`) |
| **Lambda** | Lambda Functions | Stale functions untouched >90 days (`LAM-001`), deprecated runtimes (`LAM-002`) |
| **IAM** | IAM Roles (global) | Wildcard actions/resources (`IAM-001`, `IAM-002`, `IAM-006`), `AdministratorAccess` / `IAMFullAccess` / `PowerUserAccess` (`IAM-003`, `IAM-004`, `IAM-007`), public trust policies (`IAM-005`), cross-account trusts missing `ExternalId` (`IAM-008`) |

**Intentionally Out of Scope in v1:** AWS Cost Explorer / billing APIs, CloudTrail / CloudWatch log ingestion, GuardDuty / Security Hub / AWS Config, specialized services (EKS, ECS, Redshift, ElastiCache), and customer data contents (S3 objects, DB rows).

---

## Architecture

```text
User Browser (React + Vite + Tailwind)
  ├── Static UI ──► CloudFront (SigV4 OAC) ──► Private S3 Bucket
  │
  ├── POST /scan (precheck) ──► API Gateway ──► Lambda (sync STS + 6 core permission checks)
  │
  ├── POST /scan ─────────────► API Gateway ──► Lambda (writes PENDING to DynamoDB,
  │                                             self-invokes async worker, returns 202 + scan_id)
  │
  └── GET /scan/{id}/status ──► API Gateway ──► Lambda (reads gzipped result from DynamoDB; 1h TTL)
                                                   │
                                                   ▼
                                         Worker Lambda assumes target role via
                                         sts:AssumeRole (ExternalId, 1h session)
                                                   │
                                                   ▼
                                         14 parallel read-only scanners →
                                         deterministic misconfig.evaluate()
```

---

## Target Account IAM Role Setup

1. Open **AWS IAM → Roles → Create Role**.
2. Choose **AWS account → Another AWS account** and enter your deployed AWS Clarity account ID (`terraform -chdir=infra output -raw app_account_id`).
3. Check **Require external ID** and enter your chosen External ID (default `aws-clarity-scan`, or generate a unique ID in the AWS Clarity setup screen).
4. Attach the following exact 25-action read-only inline policy:

```json
{
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
}
```

5. Copy the resulting Role ARN into AWS Clarity, click **Test Permissions**, and run your scan.

---

## Local Testing & Development

### Backend Tests
```bash
python3 -m unittest discover -s backend -p "test_*.py" -v
```

### Frontend Dev, Lint & Build
```bash
cd frontend
cp .env.example .env   # populate VITE_API_URL and VITE_APP_ACCOUNT_ID
npm ci
npm run lint
npm run build
npm run dev
```

---

## Deployment & Teardown

Deployment is automated via [deploy.yml](.github/workflows/deploy.yml) (runs backend unit tests, frontend lint/build, packages Lambda, applies Terraform, syncs S3, and invalidates CloudFront) or manually via:

```bash
# Package Lambda & apply Terraform
./rebuild.sh

# Build & deploy frontend
cd frontend
npm ci && npm run build
aws s3 sync dist/ s3://$(terraform -chdir=../infra output -raw s3_bucket_name)/ --delete
```

To tear down all AWS infrastructure cleanly:
```bash
terraform -chdir=infra destroy
```
