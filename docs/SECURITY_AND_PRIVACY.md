# Security Architecture & Privacy Data Handling

## 1. Local-First Data Flow

```text
[Customer Workstation]
  aws-clarity CLI (Python 3.10+, pinned boto3/botocore)
    ├── Uses local AWS CLI / IAM Identity Center credentials
    ├── Contacts ONLY official AWS API endpoints (*.amazonaws.com)
    └── Writes local aws-clarity-report.json (mode 0600, zero credentials)

[Customer Browser]
  Static AWS Clarity Website (CSP: connect-src 'none')
    ├── Parses imported JSON strictly in-memory
    ├── Zero report upload, zero backend API calls, zero analytics
    └── Optional local download: Full or Sanitized (Redacted) JSON / CSV
```

## 2. Scanner Network Behaviour

- **Allowed outbound destinations:** Official AWS SDK service endpoints for the regions you scan (`sts`, `ec2`, `iam`, `lambda`, `rds`, `dynamodb`, `monitoring`, `logs`, `cloudtrail`, plus `s3` only if `--include-s3-checks` is confirmed).
- **Zero telemetry or external services:** No analytics, crash reporters, update-check pings, or AWS Clarity backend URLs exist in the CLI.
- **Zero credential leakage:** Credentials are never logged, printed to stdout/stderr, or written to output reports.

## 3. Browser & Static Website Protections

- **Content Security Policy (Production Build):** `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`.
- **Untrusted JSON Import Hardening (`reportImporter.js`):**
  - Enforces a 25 MB file-size cap.
  - Strips `__proto__`, `constructor`, and `prototype` keys to prevent prototype pollution.
  - Blocks accidental import of files containing AWS credential keys (`SecretAccessKey`, `SessionToken`, `aws_secret_access_key`).
  - Blocks demo fixtures (`is_demo: true`) from mixing with real assessments.
  - Strips control characters and renders all metadata as escaped React text (never `dangerouslySetInnerHTML`, never `eval`).
- **In-Memory Processing:** Imported customer reports are kept in React memory only and cleared when the tab closes or when you click **Clear Current Assessment** in Trust & Privacy Centre.

## 4. Safe Sanitized Sharing & CSV Formula Protection

- Before exporting, AWS Clarity displays a privacy reminder that full reports contain AWS Account IDs, Resource ARNs, Resource Names, Network Configuration, Public IP addresses, and IAM metadata.
- **Best-effort sanitization:** Use **Download Sanitized JSON** or **Download Sanitized CSV** to redact common identifiers before sharing, and **always review the exported file** before posting externally (no automated sanitizer can guarantee zero remaining sensitive context inside custom resource tags or descriptions).
- **CSV Formula Injection Neutralization:** All CSV exports prefix cells starting with `=`, `+`, `-`, `@`, tab, or carriage return with a leading `'` to prevent spreadsheet formula execution.

## 5. Static Hosting Metadata, Release Status & Honest Security Limitations

- **Offline browser guarantee:** Once the static website is loaded, you can turn off your Wi-Fi before dropping your JSON report file—the entire report import, inspection, Scan Diff, and local export flow runs offline in browser memory.
- **Static host metadata:** While your AWS assessment report is never uploaded to any server, the static hosting provider serving the website (e.g., CloudFront or GitHub Pages) may still process ordinary web request metadata such as client IP address, User-Agent, and requested page URL when loading the site itself.
- **Current deployment distinction:** The hardened local branch includes a CloudFront HTTP response headers policy (`infra/cloudfront.tf`) and `v1.1.0` scanner hardening (`api_guard.py`, root block, pre-scan confirmation), which are **not yet live** on `https://dmydkbmdw1lzr.cloudfront.net/` or published to GitHub Releases until explicitly deployed and released.
- **Production account responsibility:** Local-first eliminates vendor backend compromise as a vector for exposing customer AWS accounts, **however** read-only configuration metadata can still be sensitive, supported v1 rules do not cover every AWS service or security issue, and the health score is not a security certification. Always use a dedicated read-only role/permission set and review the source code and permissions before running against production.
- **No independent penetration test or certification:** AWS Clarity is an independent open-source project and has not undergone a third-party penetration test, SOC 2 audit, or formal certification.
- **Workstation & supply-chain boundary:** Local-first does **not** protect against a compromised workstation, malicious dependency/supply-chain updates, or insecure sharing of unredacted reports. Always verify `SHA256SUMS.txt` checksums (and `gh attestation verify` once published); note that checksums verify download integrity against a manifest and are not a digital signature.
