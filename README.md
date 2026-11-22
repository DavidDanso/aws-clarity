# AWS Clarity

**A free, strictly read-only AWS account visibility and configuration assessment platform.**

Explore the interactive **Demo Mode** without connecting AWS, or connect an AWS account using a least-privilege IAM Role ARN (via an inspectable CloudFormation template or manual setup) and a stable External ID to inspect your real inventory across **10 core AWS services** and all enabled regions—with evidence-backed findings, manual remediation steps, and honest scan coverage.

![Read-Only](https://img.shields.io/badge/Access-Strictly%20Read--Only-0d9488)
![Services](https://img.shields.io/badge/v1%20Scope-10%20AWS%20Services%20%7C%2043%20Rules-1e293b)
![Free](https://img.shields.io/badge/Early%20Access-Free%20%7C%20No%20Paid%20Scanning%20APIs-10b981)
![Stack](https://img.shields.io/badge/Stack-React%20%7C%20Python%203.12%20%7C%20Terraform-334155)

---

## Table of Contents

- [Why AWS Clarity?](#why-aws-clarity)
- [Who Is It For?](#who-is-it-for)
- [Key Features & Principles](#key-features--principles)
- [Supported Services & Coverage Matrix (v1)](#supported-services--coverage-matrix-v1)
- [How It Works — Architecture & Performance](#how-it-works--architecture--performance)
- [Security & Trust Architecture](#security--trust-architecture)
- [Cost Design & Usage Safeguards](#cost-design--usage-safeguards)
- [How to Use AWS Clarity](#how-to-use-aws-clarity)
- [Local Development](#local-development)
- [Deployment & CI/CD](#deployment--cicd)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Author & Feedback](#author--feedback)

---

## Why AWS Clarity?

Understanding what is actually running inside an AWS account is unnecessarily painful:

- **Console sprawl:** Checking EC2, VPC, S3, IAM, Lambda, RDS, DynamoDB, EBS, CloudWatch, and CloudTrail across 17–32+ enabled AWS regions requires clicking through dozens of regional console pages.
- **Silent bill leaks:** Forgotten NAT Gateways, unattached EBS volumes, orphaned snapshots, unassociated Elastic IPs, stopped EC2 instances, empty provisioned DynamoDB tables, and never-expiring CloudWatch Log Groups quietly generate monthly charges.
- **Noisy or expensive tooling:** Commercial CSPM platforms are costly and complex, while AWS native tools (Config, GuardDuty, Security Hub, Cost Explorer) incur per-resource or per-request charges. Basic scripts often produce false positives (such as flagging empty default VPCs, AWS-owned DynamoDB encryption, or read-only `Describe*` IAM policies).

**AWS Clarity** solves this by focusing on the **10 most commonly used AWS services**, running **100% deterministic, context-aware checks** over free AWS read APIs, and presenting complete, honest results in seconds.

---

## Who Is It For?

- **Individual developers & cloud learners** who want to inspect sandbox/personal AWS accounts, catch leftover billable resources, and verify security hygiene without paying for third-party tools.
- **Startups & small engineering teams** who need fast, centralized visibility across all enabled AWS regions without deploying agents or giving write permissions to an external tool.
- **Cloud & security engineers** who want clear, evidence-backed findings, manual remediation instructions, and before/after scan diffs to verify fixes.

---

## Key Features & Principles

1. **Landing & Connection First:** Every session starts on the setup screen explaining the 10 supported services, coverage matrix, stable External ID, and exact 35-action read-only IAM policy (with downloadable CloudFormation template and Explore Demo mode), plus a one-click **Verify Account & Permissions** pre-check before scanning.
2. **Strictly Read-Only:** Uses only `Describe*`, `List*`, and `Get*` IAM actions. Never creates, modifies, stops, or deletes any customer resource.
3. **Complete All-Region Inventory:** Auto-discovers **all enabled AWS regions** via `ec2:DescribeRegions`, paginates every API response completely, handles global services (`S3`, `IAM`) and `CloudTrail` home regions without duplication, and never shows mock or hardcoded data.
4. **Honest Coverage Separation:** No `NOT_ASSESSED` resource status. Inventory coverage (`COMPLETE` vs `INCOMPLETE`, listing every failed service, region, reason, and missing IAM action) is tracked strictly separately from security/cost findings. A resource is only marked `HEALTHY` when every applicable rule executes and passes.
5. **Context-Aware, Evidence-Backed Findings:** Every finding includes the exact problem, affected resource, why it matters, supporting AWS API evidence, step-by-step manual fix instructions, and how to verify the fix via re-scan diffing.
6. **Fast Multi-Region Scanning (~2.4s–4.6s):** Distributed 8-worker Lambda map-reduce fan-out, parallel IAM/S3/DynamoDB collectors, `0.9s` unreachable-region fast-fail probing, and a single-round-trip sync fast path with automatic async fallback.
7. **Responsive Across All Devices:** Adaptive UI for phones (`320px+`), tablets, laptops, and desktops—featuring tappable mobile resource cards, horizontal swipe filter rails, 6-item paginated inventory, a sticky-header inspection drawer, and bottom-sheet modals on mobile.

---

## Supported Services & Coverage Matrix (v1)

AWS Clarity intentionally focuses on **10 core AWS services**, **17 resource types**, and **43 deterministic rules** (plus the `CT-000` account-level CloudTrail advisory):

| # | Service | Scope | Supported Resource Types | Implemented Deterministic Checks |
| --- | --- | --- | --- | --- |
| 1 | **EC2** | All enabled regions | EC2 Instances, Elastic IPs, Security Groups | Open all-traffic / SSH / RDP / DB ports (`SG-001`–`SG-004`), IMDSv2 enforcement (`EC2-002`), stopped instances (`EC2-001`), unassociated Elastic IPs (`EIP-001`) |
| 2 | **VPC** | All enabled regions | VPCs, Internet Gateways, NAT Gateways | Public workloads inside default VPC (`VPC-001`; empty default VPCs are `HEALTHY`), unattached IGWs (`IGW-001`), failed & ongoing-spend active NAT Gateways (`NAT-001`–`NAT-002`) |
| 3 | **S3** | Global (mapped to actual bucket region) | S3 Buckets | Public bucket policies (`S3-002`), public ACLs (`S3-003`), encryption check (`S3-004`), Block Public Access (`S3-005`) — zero object listing (`s3:ListBucket` removed) |
| 4 | **IAM** | Global | IAM Roles, IAM Users | Context-aware wildcard checks (`IAM-001`, `IAM-002`, `IAM-006` — excludes read-only `Describe/List/Get` & `/aws-service-role/`, checks conditions), admin managed policies (`IAM-003`, `IAM-004`, `IAM-007`), public & cross-account trusts (`IAM-005`, `IAM-008`), user MFA (`IAM-009`), active access keys >90d (`IAM-010`), direct user admin (`IAM-011`) |
| 5 | **Lambda** | All enabled regions | Lambda Functions | Functions unmodified >90 days (`LAM-001`), deprecated runtimes (`LAM-002`) |
| 6 | **RDS** | All enabled regions | RDS DB Instances | Publicly accessible (`RDS-001`), unencrypted storage (`RDS-002`), deletion protection disabled (`RDS-003`), automated backups disabled (`RDS-004`) |
| 7 | **DynamoDB** | All enabled regions | DynamoDB Tables | Encryption explicitly disabled (`DDB-001`; AWS-owned default encryption is `HEALTHY`), empty provisioned-capacity tables (`DDB-002`) |
| 8 | **EBS** | All enabled regions | EBS Volumes, EBS Snapshots | Unencrypted volumes (`EBS-001`), unattached volumes (`EBS-002`), orphaned snapshots from deleted volumes (`SNAP-001`) |
| 9 | **CloudWatch** | All enabled regions | CloudWatch Alarms, CloudWatch Log Groups | Disabled alarm actions (`CW-001`), `INSUFFICIENT_DATA` alarms (`CW-002`), Log Groups set to Never Expire (`CW-003`) |
| 10 | **CloudTrail** | Regional (home-region deduplicated) | CloudTrail Trails | Logging turned off (`CT-001`), single-region trail (`CT-002`), log file validation disabled (`CT-003`), plus missing-trail account advisory (`CT-000`) |

### Intentionally Out of Scope in v1
- **AWS Cost Explorer & Billing APIs:** Excluded to avoid `$0.01/request` charges. Idle/wasteful resources are detected strictly from free configuration metadata without fabricating dollar estimates.
- **Paid AWS Security Services:** Zero calls to GuardDuty, AWS Config, or Security Hub.
- **Other AWS Services:** Only the 10 services above are scanned and claimed.
- **Customer Data Contents:** Never reads S3 object data, RDS/DynamoDB rows, Lambda source code, or CloudWatch log events.

---

## How It Works — Architecture & Performance

```text
Browser (React 18 + Vite + Tailwind CSS — Mobile / Tablet / Desktop)
  ├── Static Hosting ─────────► CloudFront (SigV4 OAC) ──► Private S3 Bucket
  │   (Local dev routes via self-healing Vite proxy: /__aws_clarity_api)
  │
  ├── POST /scan (action: "precheck")
  │     └──► API Gateway ──► Lambda (STS AssumeRole + parallel 10-service permission
  │                          probes & enabled-region discovery)
  │
  ├── POST /scan (sync: true — default fast path)
  │     └──► API Gateway ──► Coordinator Lambda (1769 MB, Python 3.12, ~50 KB zip)
  │                            ├── STS AssumeRole (ExternalId, 1h temporary creds)
  │                            ├── Global Collectors in parallel: IAM Roles/Users + S3
  │                            ├── ec2:DescribeRegions (all enabled regions)
  │                            ├── Map-Reduce Fan-Out (up to 8 concurrent sub-worker
  │                            │   Lambdas, ~4 regions each, 0.9s TCP reachability probe)
  │                            └── Merge → Deduplicate → Deterministic evaluate() (43 rules)
  │                                → Return HTTP 200 directly (zero DB persistence)
  │
  └── Async Fallback (POST /scan without sync, or automatic fallback on HTTP 202 / 504)
        ├── Stores SHA-256 token_hash + live progress in DynamoDB (1h TTL; no ARN/ExternalId)
        ├── Self-invokes async worker Lambda (returns 202 + { scan_id, scan_token })
        └── GET /scan/{scan_id}/status [Header: X-Scan-Token]
              └── Constant-time token verification → live progress or gzipped scan payload
```

### Performance Optimizations
- **8-Worker Serverless Map-Reduce:** Splits enabled regions across up to 8 concurrent Lambda sub-workers (staying safely under starter account concurrency limits) with automatic local fallback if an invoke throttles.
- **Unreachable-Region Fast-Fail (`0.9s`):** Runs a fast TCP probe against `ec2.<region>.amazonaws.com:443` before launching collectors so unreachable/degraded regions report honest `FAILED` coverage in `<1s` instead of stalling the scan.
- **Parallel Collectors & Rule Evaluation:** Parallelized per-role/per-user IAM policy fetches, S3 bucket inspection, DynamoDB `DescribeTable`, S3 security checks in `evaluate()`, and `validate_permissions()` pre-checks.
- **Lean Lambda Packaging:** Uses AWS Lambda's native Python 3.12 `boto3`/`botocore` runtime (`~50 KB` zip instead of `~20 MB`), shares read-only static botocore JSON loaders across warm invocations, and caches clients per `(service, region)` with per-service locks.
- **Measured Performance:** Full 32-region, 10-service live scans complete in **~2.4s–2.7s** backend (**~3.2s–4.0s** end-to-end warm; **~4.6s–6.5s** cold).

---

## Security & Trust Architecture

- **Least-Privilege Read-Only Access:** Exactly 35 read-only IAM actions (`Describe*`, `List*`, `Get*`). Zero write, modify, stop, delete, S3 object-listing (`s3:ListBucket`), or data-read (`s3:GetObject`) permissions.
- **Confused-Deputy Protection:** Generates a stable 128-bit random `sts:ExternalId` per AWS account connection enforced during `sts:AssumeRole` (not a credential, with explicit regeneration warnings and recovery guidance).
- **Short-Lived Credentials Only:** Uses temporary 1-hour AWS STS credentials kept strictly in Lambda memory. No long-lived AWS access keys are ever requested or stored.
- **Strict Tenant Isolation & UUID Guarding:** On async scans, each scan generates a 256-bit `scan_token`; only its SHA-256 hash is stored in DynamoDB and verified via `hmac.compare_digest` against the `X-Scan-Token` header (`403` on missing/invalid token or missing hash). `GET /scan/{scan_id}/status` validates UUID format before querying DynamoDB so internal guard keys cannot be probed. Role ARNs and External IDs are never persisted in DynamoDB.
- **Public Endpoint Trade-Off (Documented):** Because `POST /scan` is public (no user login), `X-Scan-Token` isolates async scan result retrieval, while scan initiation relies on knowing both a customer's Role ARN and exact `sts:ExternalId` (mitigated by 128-bit random External IDs, atomic per-role cooldowns, concurrency caps, API Gateway throttling, and strict read-only permissions).
- **Automatic Data Expiration:** Async scan payloads are gzip-compressed and automatically deleted from DynamoDB via a 1-hour TTL. Sync scans persist nothing to DynamoDB.
- **Private Frontend Origin:** S3 bucket blocks all public access and is served exclusively through CloudFront with Origin Access Control (OAC).
- **Instant Revocation:** Clearing browser data only clears local browser storage. Deleting the CloudFormation stack or IAM role/trust policy in AWS immediately blocks all future access.

---

## Cost Design & Usage Safeguards

AWS Clarity is free to use during early access (no subscription, no credit card, no paid AI APIs, and no paid AWS security/billing APIs). Your existing AWS infrastructure charges remain your responsibility; AWS Clarity never creates chargeable resources in customer accounts.

> **Important note on hosting costs:** AWS Free Tier allowances vary by account age/type (API Gateway REST and S3 have 12-month introductory Free Tier allowances, whereas Lambda, Provisioned DynamoDB, CloudFront, and CloudWatch Logs include Always-Free allowances up to monthly usage caps). Hosting cannot be guaranteed `$0` forever under arbitrary traffic, so built-in free usage safeguards are configured in Terraform and Lambda:

| Component | Configuration & Safeguards | Free Allowance / Exposure Notes |
| --- | --- | --- |
| **AWS Lambda** | Python 3.12, `1769 MB`, ~33 GB-s per 32-region map-reduce scan; optional `lambda_reserved_concurrency`, `SCANS_ENABLED` kill-switch, atomic `MAX_CONCURRENT_SCANS` (default `3`), `SCAN_COOLDOWN_SECONDS` (`15s`), `PRECHECK_COOLDOWN_SECONDS` (`3s`) | Always-Free tier: 1M requests + 400,000 GB-s/month; paid beyond cap |
| **API Gateway (REST)** | Retained over Lambda Function URL to preserve built-in free stage throttling (`2 req/s` steady, `10` burst via `aws_api_gateway_method_settings`) and CORS error responses | 12-month Free Tier (1M REST API calls/mo); after 12 months, `$3.50/million` requests (`<$0.01/mo` at low early-access traffic) |
| **Amazon DynamoDB** | `PROVISIONED` (`10 RCU / 10 WCU`), atomic conditional guards (`1 WCU / 0 RCU`), gzipped async payloads, 1-hour TTL (sync scans write zero inventory) | Always-Free tier: 25 GB storage + **25 RCU + 25 WCU** (`10/10` uses 40% of Always-Free capacity) |
| **Amazon CloudWatch Logs** | Dedicated `/aws/lambda/aws-clarity-scanner`, `14-day` retention, no inventory/secret logging | Always-Free 5 GB ingestion + 5 GB storage/month |
| **CloudFront + Private S3** | Static SPA (`~300 KB` JS / `~80 KB` gzipped) via OAC (`default_ttl = 3600`, `max_ttl = 86400`) | CloudFront Always-Free 1 TB transfer + 10M HTTP requests/mo; S3 is 12-month Free Tier (`<$0.01/mo` after 12 months) |
| **Target Account Scanning APIs** | Strictly control-plane `Describe*`/`List*`/`Get*` APIs; `s3:ListBucket` (`ListObjectsV2`) removed | Zero Cost Explorer, GuardDuty, Config, Security Hub, or S3 LIST calls. S3 bucket-config GET calls (`$0.0004/1,000` requests after customer's 12-month S3 Free Tier) are negligible (`~$0.00004` per scan for 20 buckets) |

---

## How to Use AWS Clarity

### Step 1: Create the Read-Only IAM Role in Your Target AWS Account

1. Open **AWS IAM → Roles → Create role** (or download the inspectable CloudFormation YAML directly on the AWS Clarity setup screen).
2. Select **Trusted entity type: AWS account → Another AWS account**.
3. Enter your deployed **App Account ID** (`terraform -chdir=infra output -raw app_account_id`) and check **Require external ID**, pasting the unique External ID shown on the AWS Clarity landing screen.
4. Attach this exact **35-action read-only inline policy**:

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

### Step 2: Verify Connection & Scan

1. Paste your new IAM Role ARN (`arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>`) on the AWS Clarity landing screen.
2. Click **Verify Account & Permissions** to confirm STS role assumption, discovered enabled regions, and all 10 service permissions.
3. Click **Connect & Scan All Enabled Regions**.

### Step 3: Inspect, Fix Manually & Re-Scan to Verify

1. Review the **Scan Coverage** banner (tracked separately from security findings) and your deterministic **Health Score**.
2. Filter the 6-item paginated inventory by **Service**, **Region**, **Status / Cost Risk**, or full-text search, or export the inventory to **CSV**.
3. Click any resource to open the **Detail Drawer** with supporting AWS API evidence, copyable manual fix instructions, and verification steps.
4. Apply fixes manually in the AWS Console/CLI/Terraform, then click **Re-scan Account** to view the live **Scan Diff** (`Resolved`, `Still Open`, `New Issues`, `New/Removed Resources`, `Status Changes`).

---

## Local Development

### Prerequisites
- **Python 3.12+** (with `boto3` / `botocore` for running unit tests)
- **Node.js 20+** and `npm`
- **Terraform `~> 1.15`** and **AWS CLI v2** (configured with credentials for your hosting AWS account)

### 1. Run Backend Unit Tests (23 Tests)
```bash
pip install -r backend/requirements.txt
python3 -m unittest discover -s backend -p "test_*.py" -v
```

### 2. Run the Frontend Locally
```bash
cd frontend
npm ci
npm run dev
```

#### Automatic Environment Sync & Self-Healing Dev Proxy
You do **not** need to manually update `frontend/.env` when the backend API Gateway is recreated:
- **`predev` (`frontend/scripts/sync-env.mjs`):** Automatically runs before `npm run dev` (or on demand via `npm run sync-env`) to discover the live `aws-clarity-api` endpoint from AWS API Gateway (with Terraform output fallback) and sync `frontend/.env`.
- **Self-Healing Vite Dev Proxy (`frontend/vite.config.js`):** In dev mode, browser requests route through `/__aws_clarity_api`. If you destroy and redeploy the stack (e.g., via GitHub Actions) while `localhost:5173` is already running, Vite detects the stale endpoint, discovers the new API Gateway URL, updates `frontend/.env`, and seamlessly retries the request without restarting the dev server.

### 3. Frontend Lint & Production Build
```bash
cd frontend
npm run lint
npm run build
```

---

## Deployment & CI/CD

### Option A: Local Deployment (`rebuild.sh`)
Builds the lean Lambda zip, applies Terraform infrastructure, and syncs `frontend/.env`:
```bash
./rebuild.sh
```
To deploy the frontend static bundle to S3 and invalidate CloudFront:
```bash
cd frontend && npm run build && cd ..
S3_BUCKET=$(terraform -chdir=infra output -raw s3_bucket_name)
aws s3 sync frontend/dist/ "s3://${S3_BUCKET}" --delete
```

### Option B: Automated GitHub Actions (`.github/workflows/deploy.yml`)
Pushes to `main` touching `backend/**`, `frontend/**`, or `infra/**` automatically:
1. Run all Python backend unit tests (`unittest`) and frontend checks (`npm run lint`, `npm run build`).
2. Package the lean Lambda archive (`infra/lambda.zip`).
3. Run `terraform init`, `validate`, `plan`, and `apply` (using the remote S3 state backend configured in `infra/main.tf`).
4. Build `frontend/dist` with live Terraform outputs, sync to the private S3 bucket, and invalidate CloudFront.

Manual `workflow_dispatch` supports both `deploy` and full `destroy` teardown.

### Clean Teardown
```bash
terraform -chdir=infra destroy
```

---

## API Reference

Base URL: `terraform -chdir=infra output -raw api_gateway_url`

| Endpoint | Method | Request / Headers | Behavior |
| --- | --- | --- | --- |
| `/scan` | `POST` | `{ "role_arn": "...", "external_id": "...", "action": "precheck" }` | Verifies STS identity, discovers enabled regions, and probes all 10 service permissions in parallel (`200`). |
| `/scan` | `POST` | `{ "role_arn": "...", "external_id": "...", "regions": "all", "sync": true }` | Single-round-trip 8-worker map-reduce scan returning the full inventory, findings, and coverage directly (`200`, zero DynamoDB storage). |
| `/scan` | `POST` | `{ "role_arn": "...", "external_id": "...", "regions": "all" }` | Async scan: stores SHA-256 `token_hash` in DynamoDB, invokes background worker, returns `202 { scan_id, scan_token }`. |
| `/scan/{scan_id}/status` | `GET` | Header: `X-Scan-Token: <scan_token>` | Validates token in constant time (`403` if invalid); returns live progress while `RUNNING` or decompressed full results once `COMPLETE` / `INCOMPLETE`. |

---

## Project Structure

```text
aws-clarity/
├── .github/workflows/
│   └── deploy.yml                  # CI/CD: test, build, Terraform deploy/destroy, S3 & CloudFront sync
├── backend/
│   ├── lambda_handler.py           # API handlers, 8-worker map-reduce coordinator, region_batch & async worker
│   ├── utils.py                    # Validation, STS AssumeRole, CachedSession, static botocore loader, token hashing
│   ├── exceptions.py               # Typed scanner, ARN, STS, and permission exceptions
│   ├── requirements.txt            # Local/CI dev dependencies (Lambda uses native runtime boto3/botocore)
│   ├── test_detection_coverage.py  # Scope, security, pagination, accuracy, fast-fail & sync path tests
│   ├── test_misconfig_eval.py      # Deterministic rule engine smoke tests
│   ├── test_s3_region.py           # Global S3 discovery & region filtering tests
│   └── scanner/
│       ├── misconfig.py            # SERVICE_COVERAGE_MATRIX, 43 deterministic rules & parallel S3 evaluation
│       ├── ec2.py                  # EC2 instances (paginated)
│       ├── elastic_ip.py           # Elastic IPs
│       ├── security_group.py       # Security Groups (paginated)
│       ├── vpcs.py                 # VPCs (paginated)
│       ├── internet_gateways.py    # Internet Gateways (paginated)
│       ├── nat_gateways.py         # NAT Gateways (paginated)
│       ├── s3.py                   # Global S3 buckets + parallel location/object/versioning inspection
│       ├── iam.py                  # Parallel IAM roles & users (policies, MFA, access keys, trusts)
│       ├── lambda_functions.py     # Lambda functions (paginated)
│       ├── rds.py                  # RDS DB instances (paginated)
│       ├── dynamodb_tables.py      # DynamoDB tables + parallel DescribeTable
│       ├── ebs.py                  # EBS volumes (paginated)
│       ├── snapshots.py            # Self-owned EBS snapshots (paginated)
│       ├── cloudwatch.py           # CloudWatch metric/composite alarms & Log Groups (paginated)
│       └── cloudtrail.py           # Home-region deduplicated CloudTrail trails & logging status
├── frontend/
│   ├── scripts/sync-env.mjs        # Auto-discovers live AWS API Gateway URL & syncs frontend/.env
│   ├── vite.config.js              # Vite config with self-healing /__aws_clarity_api dev proxy
│   └── src/
│       ├── App.jsx                 # Landing-first router, session state, floating feedback menu
│       ├── pages/
│       │   ├── SetupScreen.jsx     # Landing page, 10-service matrix, External ID, IAM guide & pre-check
│       │   └── DashboardScreen.jsx # Coverage banner, score ring, scan diff, live progress & inventory
│       ├── components/
│       │   ├── TopBar.jsx          # Responsive header with account metadata & quick actions
│       │   ├── ResourceTable.jsx   # Responsive mobile cards / desktop table (6/page), filters & search
│       │   ├── DetailDrawer.jsx    # Sticky-header slide-over drawer with evidence, fix & verify steps
│       │   ├── CoverageModal.jsx   # Separate inventory coverage & failed regions/permissions breakdown
│       │   ├── ScoreModal.jsx      # Transparent deterministic score formula & live calculation
│       │   ├── ChecksCatalogModal.jsx # Searchable 43-rule catalog with live account status
│       │   └── TrustModal.jsx      # Trust & Privacy Centre, security boundaries & separated Data Controls
│       ├── services/api.js         # Sync-first scan client, async 400ms fallback polling & pre-check
│       └── utils/                  # Constants, IAM policy JSON, CloudFormation generator, connectionStorage, score & scan diff
├── infra/
│   ├── main.tf                     # Terraform ~> 1.15, AWS provider ~> 6.0, remote S3 state backend
│   ├── variables.tf                # Region, app name, Lambda memory (1769 MB), timeout (120s), log retention (14d), capacity & throttles
│   ├── iam.tf                      # Lambda execution role + sample 35-action AWSClarityReadOnly role
│   ├── lambda.tf                   # aws-clarity-backend Lambda + managed /aws/lambda/aws-clarity-scanner log group
│   ├── api_gateway.tf              # REST API, stage throttling (2 req/s, 10 burst), CORS preflight & CORS 4XX/5XX responses
│   ├── dynamodb.tf                 # Provisioned scan state table (10 RCU / 10 WCU — Always-Free tier) with 1h TTL
│   ├── s3_hosting.tf               # Private S3 frontend bucket + public access block
│   ├── cloudfront.tf               # CloudFront CDN with SigV4 OAC
│   └── outputs.tf                  # API URL, CloudFront URL, Lambda name, S3 bucket, App Account ID
└── rebuild.sh                      # Lean Lambda packaging, Terraform apply & frontend/.env sync script
```

---

## Author & Feedback

Built by **[David Danso](https://www.linkedin.com/in/david-danso/)** — AWS Cloud Engineer.

- [Report a Bug](https://github.com/DavidDanso/aws-clarity/issues/new?template=bug_report.md&title=[Bug])
- [Request a Feature](https://github.com/DavidDanso/aws-clarity/issues/new?template=feature_request.md&title=[Feature])
