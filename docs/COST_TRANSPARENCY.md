# Cost Transparency (Hosting & Customer AWS Accounts)

AWS Clarity has a **\$0 subscription fee** for users (free, open-source MIT software with no paid AI and no hosted backend database). Actual operating costs depend on where the static website is hosted and which AWS APIs you run locally. Both sides are documented transparently below.

---

## 1. Website Hosting (Owner-Operated Static Site)

Because scanning runs locally via the Python CLI and report viewing runs 100% in the browser, AWS Clarity requires **only static file hosting** (~370 KB built bundle).

| Static Host | Current Published Free Tier / Plan Limits | Automatic Paid Overage? | Operational Notes |
| --- | --- | --- | --- |
| **GitHub Pages** *(Recommended canonical host)* | Public repo static hosting; 1 GB published site limit; soft limits of 100 GB bandwidth/month and 10 builds/hour (subject to GitHub Terms of Service) | **No** (no credit card required for public repos) | Free under current GitHub Pages public-repo terms (`https://daviddanso.github.io/aws-clarity/`). Does not support custom HTTP response headers (relies on HTML `<meta>` CSP). |
| **Cloudflare Pages (Free)** | Unlimited static requests & bandwidth; 500 builds/month; 25 MB/file (subject to Cloudflare plan terms) | **No** (static tier stays free unless paid add-ons are enabled) | Supports custom HTTP response headers (`Content-Security-Policy` with `frame-ancestors 'none'`, HSTS, etc.). |
| **AWS CloudFront + S3 (Optional Mirror)** | CloudFront Free Tier (1 TB data transfer + 10M HTTP/HTTPS requests/month); S3 Free Tier is 12 months only for new AWS accounts | **Yes** (AWS account bills S3 storage/requests after 12 months and any CloudFront usage above free caps) | Supports `aws_cloudfront_response_headers_policy` HTTP security headers; billed to the project owner's AWS account if free limits are exceeded. |

> **Honest qualification:** No third-party hosting provider guarantees permanent \$0 pricing forever—providers can update free-tier terms, enforce soft bandwidth caps, or rate-limit traffic. Optional extras such as a custom domain name also carry registrar fees paid by the project owner. PyPI hosting for open-source packages is currently free, subject to PyPI's policies.

---

## 2. Customer-Side Local Requirements & AWS API Pricing Audit

Users need only a workstation with Python 3.10+ and their existing AWS CLI / IAM Identity Center setup. AWS Clarity never creates billable resources in customer AWS accounts and never calls paid AWS security/billing APIs (Cost Explorer, GuardDuty, AWS Config, Security Hub).

### Default Scan (9 Services — \$0 AWS API Request Pricing)

The default `aws-clarity scan` runs only **28 AWS control-plane read actions** that carry **\$0 per-request AWS API charges**:
- `sts:GetCallerIdentity` *(plus `sts:AssumeRole` only when `--role-arn` is explicitly passed)*
- `ec2:DescribeRegions`, `DescribeInstances`, `DescribeAddresses`, `DescribeSecurityGroups`, `DescribeVpcs`, `DescribeInternetGateways`, `DescribeNatGateways`, `DescribeVolumes`, `DescribeSnapshots`
- `iam:ListRoles`, `ListRolePolicies`, `GetRolePolicy`, `ListAttachedRolePolicies`, `ListUsers`, `ListMFADevices`, `ListAccessKeys`, `ListAttachedUserPolicies`, `ListUserPolicies`, `GetUserPolicy`
- `lambda:ListFunctions`
- `rds:DescribeDBInstances`
- `dynamodb:ListTables`, `DescribeTable`
- `cloudwatch:DescribeAlarms`, `logs:DescribeLogGroups`
- `cloudtrail:DescribeTrails`, `GetTrailStatus`

*(Note: AWS can change service pricing at any time; verify current AWS pricing documentation if running at large enterprise scale.)*

### Optional Opt-In Checks (S3)

AWS S3 bills standard LIST and GET API requests outside an account's 12-month S3 Free Tier (`2,000 LIST` + `20,000 GET` requests/month):
- **`s3:ListBucket` (`ListObjectsV2`) & `S3-001` (empty bucket):** **Permanently removed** to avoid per-bucket object-listing charges.
- **`s3:GetBucketVersioning`:** **Removed** because no rule required it.
- **Remaining S3 checks (`S3-002`–`S3-005`):** Make `1 ListAllMyBuckets` (LIST, standard list price \$0.005/1,000) + `5 GetBucket*` (GET, standard list price \$0.0004/1,000) calls per bucket (roughly \$0.00004 per scan for 20 buckets outside Free Tier).
  - **Skipped by default** (`SKIPPED_OPTIONAL` — never marked `HEALTHY` or `PASSED`).
  - Requires explicit `--include-s3-checks` flag **plus** interactive confirmation (`[y/N]`) or `--confirm-s3-request-costs`.
