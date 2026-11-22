# Cost Transparency (Hosting & Customer AWS Accounts)

AWS Clarity is free to use (\$0 subscription, no paid AI, no paid backend database). Both hosting costs and customer-side AWS API costs are documented transparently below.

---

## 1. Website Hosting (Verified \$0 Static Hosting Options)

Because scanning runs locally via the Python CLI and report viewing runs 100% in the browser, AWS Clarity requires **only static file hosting** (~400 KB built bundle).

| Static Host | Free Plan Limits | Automatic Paid Upgrade? | Suitability |
| --- | --- | --- | --- |
| **GitHub Pages** *(Recommended)* | Public repo static hosting; 1 GB site size; soft limit 100 GB bandwidth/mo & 10 builds/hr | **No** (no credit card required; cannot silently bill) | **Best fit for guaranteed \$0 hosting** — serves directly from the public repo (`https://<user>.github.io/aws-clarity/`), zero cloud billing account needed. |
| **Cloudflare Pages (Free)** | Unlimited static requests & bandwidth; 500 builds/mo; 25 MB/file | **No** (static asset hosting stays free; no forced upgrade) | Excellent alternative with built-in CDN & custom response headers (`Content-Security-Policy`). |
| **AWS CloudFront + S3 (Existing Legacy)** | CloudFront Always-Free (1 TB/mo + 10M reqs); S3 Free Tier expires after 12 months | **Yes** (AWS account bills S3 storage/requests after 12 months and overages above caps) | Retain only temporarily during migration; prefer GitHub Pages or Cloudflare Pages for strict \$0 operation. |

> **Honest qualification:** Third-party free hosting providers can change plan terms or rate-limit/pause a site if free quotas are exceeded. Choosing GitHub Pages or Cloudflare Pages (without attaching paid add-ons) ensures quota exhaustion pauses availability rather than silently incurring credit card charges.

---

## 2. Customer-Side AWS API Pricing Audit

AWS Clarity never creates billable resources in customer accounts and never calls paid AWS security/billing APIs (Cost Explorer, GuardDuty, AWS Config, Security Hub).

### Default Scan (9 Services — Zero Request Charges)

The default `aws-clarity scan` runs only control-plane read operations with **\$0 AWS API request pricing**:
- `sts:GetCallerIdentity`
- `ec2:DescribeRegions`, `DescribeInstances`, `DescribeAddresses`, `DescribeSecurityGroups`, `DescribeVpcs`, `DescribeInternetGateways`, `DescribeNatGateways`, `DescribeVolumes`, `DescribeSnapshots`
- `iam:ListRoles`, `ListRolePolicies`, `GetRolePolicy`, `ListAttachedRolePolicies`, `ListUsers`, `ListMFADevices`, `ListAccessKeys`, `ListAttachedUserPolicies`, `ListUserPolicies`, `GetUserPolicy`
- `lambda:ListFunctions`
- `rds:DescribeDBInstances`
- `dynamodb:ListTables`, `DescribeTable`
- `cloudwatch:DescribeAlarms`, `logs:DescribeLogGroups`
- `cloudtrail:DescribeTrails`, `GetTrailStatus`

### Optional Opt-In Checks (S3)

AWS S3 prices API requests outside an account's 12-month S3 Free Tier (`2,000 LIST` + `20,000 GET` requests/month):
- **`s3:ListBucket` (`ListObjectsV2`) & `S3-001` (empty bucket):** **Permanently removed** to avoid per-bucket LIST charges.
- **`s3:GetBucketVersioning`:** **Removed** because no rule required it.
- **Remaining S3 checks (`S3-002`–`S3-005`):** Make `1 ListAllMyBuckets` (LIST, \$0.005/1,000) + `5 GetBucket*` (GET, \$0.0004/1,000) calls per bucket (e.g., ~\$0.00004 per scan for 20 buckets).
  - **Skipped by default** (`SKIPPED_OPTIONAL` — never marked `HEALTHY` or `PASSED`).
  - Requires explicit `--include-s3-checks` flag **plus** interactive confirmation (`[y/N]`) or `--confirm-s3-request-costs`.
