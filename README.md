# AWS Clarity

**AWS Clarity** is a secure, strictly read-only AWS account visibility platform. Connect an AWS account using an IAM Role ARN and a unique External ID to discover your real AWS inventory across **all enabled regions**, identify security risks and unused/wasteful resources, and get practical remediation + verification steps—all from one central dashboard.

---

## Core Design Principles

1. **Landing & Connection First:** Users always start on the landing and account-connection screen, see the exact 10 supported services and coverage matrix, verify their account identity and permissions, and then transition to their account dashboard.
2. **Strictly Read-Only:** Requests exclusively 36 least-privilege `Describe*`, `List*`, and `Get*` IAM actions. Never creates, modifies, stops, or deletes customer AWS resources.
3. **Complete & Accurate Inventory:** Auto-discovers **all enabled AWS regions** (`ec2:DescribeRegions`), handles global services (`S3`, `IAM`) cleanly, paginates every AWS API call, deduplicates by canonical AWS identifier, and never fabricates data.
4. **Honest Coverage & Accurate Findings:** No `NOT_ASSESSED` resource status. Inventory coverage (`COMPLETE` vs `INCOMPLETE` with exact failed services, regions, and reasons) is tracked strictly separately from deterministic security/cost assessment results. Resources are only marked `HEALTHY` when every applicable implemented check runs and passes.
5. **Strong Security & Tenant Isolation:** Unique per-session `sts:ExternalId`, temporary 1-hour STS sessions, 256-bit ephemeral `X-Scan-Token` (SHA-256 verified) isolating every scan result, never storing Role ARNs or External IDs in DynamoDB, and 1-hour automatic DynamoDB TTL cleanup.
6. **Zero-Cost Priority:** Zero paid AWS APIs (no Cost Explorer, GuardDuty, AWS Config, or Security Hub) and Free Tier–friendly serverless hosting (CloudFront + private S3, API Gateway, 512 MB Lambda with 14-day CloudWatch log retention, on-demand DynamoDB with gzip-compressed payloads and 1-hour TTL).

---

## Fixed v1 Scope — 10 Supported AWS Services & Resource Coverage Matrix

| # | Service | Scope | Supported Resource Types | Implemented Deterministic Checks |
|---|---|---|---|---|
| 1 | **EC2** | All enabled regions | EC2 Instances, Elastic IPs, Security Groups | Open all-traffic/SSH/RDP/database ports (`SG-001`–`SG-004`), IMDSv2 (`EC2-002`), stopped instances (`EC2-001`), idle Elastic IPs (`EIP-001`) |
| 2 | **VPC** | All enabled regions | VPCs, Internet Gateways, NAT Gateways | Public workloads inside default VPC (`VPC-001` — empty default VPC is healthy), unattached IGWs (`IGW-001`), failed & bill-generating active NAT Gateways (`NAT-001`–`NAT-002`) |
| 3 | **S3** | Global (actual bucket region) | S3 Buckets | Public policies (`S3-002`), public ACLs (`S3-003`), Block Public Access (`S3-005`), encryption check (`S3-004`), empty buckets (`S3-001`) |
| 4 | **IAM** | Global | IAM Roles, IAM Users | Context-aware wildcard evaluation (`IAM-001`, `IAM-002`, `IAM-006` — excludes read-only `Describe/List/Get` & service-linked roles, checks conditions), admin managed policies (`IAM-003`, `IAM-004`, `IAM-007`), public & cross-account trusts (`IAM-005`, `IAM-008`), user MFA (`IAM-009`), stale access keys >90d (`IAM-010`), direct user admin (`IAM-011`) |
| 5 | **Lambda** | All enabled regions | Lambda Functions | Stale functions >90 days (`LAM-001`), deprecated runtimes (`LAM-002`) |
| 6 | **RDS** | All enabled regions | RDS DB Instances | Publicly accessible (`RDS-001`), unencrypted storage (`RDS-002`), deletion protection (`RDS-003`), automated backups disabled (`RDS-004`) |
| 7 | **DynamoDB** | All enabled regions | DynamoDB Tables | Explicit encryption disabled (`DDB-001` — AWS-owned default encryption passes), empty provisioned-capacity tables (`DDB-002`) |
| 8 | **EBS** | All enabled regions | EBS Volumes, EBS Snapshots | Unencrypted volumes (`EBS-001`), unattached volumes (`EBS-002`), orphaned snapshots (`SNAP-001`) |
| 9 | **CloudWatch** | All enabled regions | CloudWatch Alarms, CloudWatch Log Groups | Disabled alarm actions (`CW-001`), `INSUFFICIENT_DATA` alarms (`CW-002`), Log Groups set to Never Expire (`CW-003`) |
| 10 | **CloudTrail** | Home-region deduplicated | CloudTrail Trails | Logging disabled (`CT-001`), single-region trail (`CT-002`), log file validation disabled (`CT-003`), plus missing-trail account advisory (`CT-000`) |

---

## Architecture

```text
User Browser (React + Vite + Tailwind)
  ├── Landing & Connection Screen ──► CloudFront (SigV4 OAC) ──► Private S3 Bucket
  │
  ├── POST /scan (action: precheck) ─► API Gateway ─► Lambda (verifies STS identity, discovers
  │                                                    enabled regions & probes 10 services)
  │
  ├── POST /scan (regions: "all") ───► API Gateway ─► Lambda (stores token_hash in DynamoDB,
  │                                                    self-invokes async worker, returns
  │                                                    202 + { scan_id, scan_token })
  │
  └── GET /scan/{id}/status ─────────► API Gateway ─► Lambda (verifies X-Scan-Token via SHA-256
       [Header: X-Scan-Token]                          constant-time compare, returns gzipped result)
                                                         │
                                                         ▼
                                               Worker assumes target role (ExternalId, 1h STS) →
                                               discovers all enabled regions → 17 paginated
                                               collectors across 10 services → deduplicate →
                                               deterministic evaluate() → gzip + DynamoDB (1h TTL)
```

---

## Target Account IAM Role Setup

1. Open **AWS IAM → Roles → Create Role**.
2. Choose **AWS account → Another AWS account**, enter your deployed App Account ID (`terraform -chdir=infra output -raw app_account_id`), and check **Require external ID** using the unique External ID shown on the AWS Clarity connection screen.
3. Attach this exact 36-action least-privilege read-only inline policy:

```json
{
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
}
```

---

## Testing & Deployment

### Run Backend Tests
```bash
python3 -m unittest discover -s backend -p "test_*.py" -v
```

### Lint, Build & Develop Frontend
```bash
cd frontend
cp .env.example .env
npm ci
npm run lint
npm run build
npm run dev
```

### Deploy & Tear Down
Automated via [.github/workflows/deploy.yml](.github/workflows/deploy.yml) or locally:
```bash
./rebuild.sh
terraform -chdir=infra destroy   # clean full teardown
```
