# Legacy Hosted Infrastructure Migration & Safe Decommissioning Plan

> **Important:** Do **not** run destructive teardown commands until you have published the static frontend to your chosen \$0 static host (e.g., GitHub Pages or Cloudflare Pages) and confirmed all users have moved to the local-first workflow.

## 1. Current Terraform-Managed Resource Audit

| Resource | Purpose in Legacy Hosted Mode | Required in Local-First Mode? | Cost Exposure if Left Running | Recommended Action |
| --- | --- | --- | --- | --- |
| `aws_api_gateway_rest_api.api` + stage/methods/responses (`8qyvhlsume`) | Public anonymous `POST /scan` & `GET /scan/{id}/status` | **No** | 12-mo Free Tier, then \$3.50/M requests | **Decommission** (remove public attack surface & ongoing cost) |
| `aws_lambda_function.scanner` (`aws-clarity-backend`) + `aws_lambda_permission.apigw` | Central cross-account scanner executing `sts:AssumeRole` | **No** | Always-Free up to 1M req / 400k GB-s | **Decommission** (eliminates central cross-account STS role) |
| `aws_iam_role.lambda_exec`, `aws_iam_policy.lambda_cross_account`, `aws_iam_role_policy.lambda_scan_state` | Grants Lambda `sts:AssumeRole` on `arn:aws:iam::*:role/*` & DynamoDB access | **No** | \$0 (IAM is free) | **Decommission** (eliminates wildcard cross-account AssumeRole capability) |
| `aws_iam_role.clarity_read_only` + `clarity_read_only_policy` | Owner's sample read-only test role (`AWSClarityReadOnly`) | Optional (local testing only) | \$0 | **Decommission or convert** trust policy to your own local AWS user/SSO role (remove `lambda_exec` trust & `aws-clarity-scan`) |
| `aws_dynamodb_table.scans` (`aws-clarity-scans`) | Async scan results, rate limits, concurrency counter | **No** | Provisioned `10 RCU / 10 WCU` (within 25/25 Always-Free) | **Decommission** (no central database needed) |
| `aws_cloudwatch_log_group.scanner` (`/aws/lambda/aws-clarity-scanner`) | Lambda execution logs (14-day retention) | **No** | Always-Free up to 5 GB | **Decommission** after exporting any needed logs |
| `aws_cloudfront_distribution.frontend` (`E1R8FZ59T81NWG`) + OAC | Hosts static React SPA | Optional (temporary bridge) | CloudFront Always-Free (1 TB / 10M req) | **Retain temporarily** during DNS/link cutover to GitHub Pages or Cloudflare Pages, then decommission |
| `aws_s3_bucket.frontend` (`aws-clarity-frontend-...`) + policy + PAB | Static SPA origin bucket | Optional (temporary bridge) | 12-mo Free Tier, then <\$0.01/mo | **Retain temporarily** alongside CloudFront until static host cutover is verified |
| **External:** S3 bucket `cloudlabs-tf-state` (`key = aws-clarity/terraform.tfstate`) | Remote Terraform state storage (created outside this stack) | **DO NOT DESTROY automatically** | Tiny S3 object (<\$0.01/mo) | **MANUAL REVIEW REQUIRED** — may be shared with other Terraform projects; retain or archive state manually |

---

## 2. Recommended Safe Decommissioning Sequence (Zero Risk of Accidental Loss)

### Phase 1: Immediate Risk Reduction (Pause Hosted Scanning — Reversible)
`infra/variables.tf` now sets `scans_enabled = false` by default. If you need an immediate stop-gap before decommissioning:
1. Run `terraform -chdir=infra plan` to confirm only `SCANS_ENABLED = "false"` changes on `aws_lambda_function.scanner`.
2. Apply that single change so `POST /scan` immediately returns HTTP `503 SCANS_PAUSED` and refuses all cross-account `sts:AssumeRole` calls.

### Phase 2: Publish Static Local-First Website to Free Static Hosting
Option A — **GitHub Pages (Recommended — Zero Billing Account):**
1. Build the production static site (`cd frontend && npm ci && npm run build`).
2. Verify `frontend/dist/index.html` contains `Content-Security-Policy` with `connect-src 'none'`.
3. Enable GitHub Pages via GitHub Actions (`actions/deploy-pages`) deploying `frontend/dist/`.

Option B — **Cloudflare Pages (Free Tier):**
1. Connect repository with build command `cd frontend && npm ci && npm run build` and output directory `frontend/dist`.
2. Verify no paid Workers/add-ons are enabled.

### Phase 3: Remove Hosted Backend Resources (Keep Static Bridge Until Verified)
Once the new static site is live and verified:
1. Verify no active automation/CI relies on `https://8qyvhlsume.execute-api.us-east-1.amazonaws.com/prod`.
2. Remove backend Terraform resources (API Gateway, Lambda, DynamoDB, CloudWatch Log Group, `lambda_exec` IAM role & cross-account policy) via targeted removal or full `terraform -chdir=infra destroy` once CloudFront/S3 cutover is complete:
   ```bash
   # Preview first — NEVER destroy blindly
   terraform -chdir=infra plan -destroy
   ```
3. Confirm in AWS IAM that `aws-clarity-lambda-exec` and `aws-clarity-assume-roles` no longer exist.
4. **Leave `cloudlabs-tf-state` untouched** unless you have verified no other stacks share that bucket.

### Rollback Path
- Because this pre-launch update does not alter live AWS infrastructure, the existing deployment remains untouched until you explicitly execute Phase 1–3.
- Legacy backend files (`backend/lambda_handler.py`, `infra/*.tf`) remain in Git history and on disk with `scans_enabled = false` by default if ever needed for private self-hosted evaluation.
