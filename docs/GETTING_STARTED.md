# Getting Started & Local Scanner Installation

AWS Clarity runs **locally on your computer** using your existing AWS CLI or IAM Identity Center (AWS SSO) credentials. Your AWS credentials and account inventory never leave your environment.

## Prerequisites

- **Python 3.10+** (macOS, Linux, or Windows)
- **AWS CLI v2** configured with a profile or IAM Identity Center (`aws sso login`)
- A read-only IAM policy attached to your own IAM role or IAM Identity Center permission set (see [IAM Permissions](./IAM_PERMISSIONS.md))

## 1. Install the Local Scanner

Install directly from the inspectable public source repository into an isolated virtual environment:

```bash
git clone https://github.com/DavidDanso/aws-clarity.git
cd aws-clarity
python3 -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install .
```

Verify installation:

```bash
aws-clarity version
```

To verify a packaged release archive before installing:

```bash
shasum -a 256 -c SHA256SUMS.txt
```

## 2. Authenticate With Your Existing AWS Profile

AWS Clarity uses the standard AWS SDK (`boto3`) credential provider chain. It never asks for permanent access keys through the website.

```bash
# If using IAM Identity Center (AWS SSO):
aws sso login --profile my-profile

# Confirm which AWS account you are targeting before scanning:
aws sts get-caller-identity --profile my-profile
```

## 3. Check Permissions Locally (`doctor`)

Do not assume authentication means all read-only permissions are present. Run `doctor` first:

```bash
aws-clarity doctor --profile my-profile
```

Optional: also probe S3 permissions if you intend to opt into S3 checks:

```bash
aws-clarity doctor --profile my-profile --include-s3-checks
```

## 4. Run a Local Read-Only Assessment (`scan`)

Default scan (**9 zero-request-charge control-plane services**, S3 intentionally skipped as optional):

```bash
aws-clarity scan --profile my-profile --output aws-clarity-report.json
```

Optional: include S3 bucket security checks (displays AWS S3 request pricing and requires explicit consent):

```bash
aws-clarity scan --profile my-profile --include-s3-checks --output aws-clarity-report.json
```

For non-interactive automation after reviewing the cost disclosure:

```bash
aws-clarity scan --profile my-profile --include-s3-checks --confirm-s3-request-costs --output aws-clarity-report.json
```

Using a customer-owned read-only IAM role from your local profile (no AWS Clarity account involved):

```bash
aws-clarity scan --profile my-profile --role-arn arn:aws:iam::123456789012:role/MyReadOnlyRole --output aws-clarity-report.json
```

Reports are saved locally with owner-only `0600` file permissions on macOS/Linux (POSIX); on Windows, standard user directory ACLs apply. Reports never contain AWS credentials.

## 5. View & Compare Reports Locally in Your Browser

1. Open the AWS Clarity static website.
2. Click **Import Assessment Report (.json)** and select `aws-clarity-report.json`.
3. Inspect findings, supporting AWS API evidence, coverage, and safe manual remediation steps.
4. After applying fixes manually in AWS, run `aws-clarity scan` again to produce a new report, then click **Import Newer Report (Diff)** in the dashboard to compare **New**, **Resolved**, and **Unchanged** findings locally in memory.

## Team Usage & Limitations

- Individual developers and small teams can use AWS Clarity without registering for an account or sharing a central database.
- Each engineer runs `aws-clarity scan` using their own authorized AWS CLI / IAM Identity Center profile.
- Use **Export / Share Report → Download Sanitized JSON** (or Sanitized CSV) when sharing results outside your immediate team; sanitized exports redact AWS Account IDs, ARNs, resource names, IP addresses, and raw IAM/network payloads.
- AWS Clarity v1 intentionally does **not** include user login, shared team databases, multi-account org dashboards, or automatic remediation.
