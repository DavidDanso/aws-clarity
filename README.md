# AWS Clarity

**Free, privacy-first, local-only AWS account visibility and configuration assessment.**

Run the open-source, strictly read-only `aws-clarity` CLI on your own computer using your existing AWS CLI or IAM Identity Center (SSO) profile, then import the generated JSON report into the static AWS Clarity web dashboard—completely in browser memory, with **zero backend servers, zero central credential handling, and zero report uploads**.

![Privacy](https://img.shields.io/badge/Architecture-Local--First%20%7C%20Zero%20Backend-0d9488)
![Access](https://img.shields.io/badge/Access-Strictly%20Read--Only-0f766e)
![Scope](https://img.shields.io/badge/v1%20Scope-10%20AWS%20Services%20%7C%2043%20Rules-1e293b)
![Price](https://img.shields.io/badge/Cost-Free%20(%240%20Subscription)-10b981)

---

## Why Local-First?

With a hosted scanning architecture, customers must grant a vendor's servers cross-account access to their AWS environment—meaning a compromise of the vendor's backend could expose customer infrastructure metadata.

With **AWS Clarity Local-First**:
- **Credentials stay with you:** Uses your local AWS CLI / IAM Identity Center (`aws sso login`) credentials. Never asks for permanent AWS access keys or vendor cross-account trust relationships.
- **Inventory stays local:** The CLI talks directly to official AWS endpoints and writes `aws-clarity-report.json` locally (`0600`).
- **Offline browser viewing:** The static website parses imported reports strictly in memory and enforces `Content-Security-Policy: connect-src 'none'` on production builds—no report uploads, no analytics, no central database.
- **Cost-conscious by default:** Default scans run **9 zero-request-charge AWS control-plane services** (28 actions) and skip S3 (`SKIPPED_OPTIONAL`) unless you explicitly opt in (`--include-s3-checks`) after reviewing S3 API pricing.

> **Honest security note:** Local-first eliminates vendor backend exposure, but no software can guarantee zero breach risk. Protect your workstation and local report files, inspect open-source updates, and verify `SHA256SUMS.txt` checksums before installing releases.

---

## Quick Start

```bash
# 1. Install the local CLI from source (Python 3.10+)
python3 -m venv .venv && source .venv/bin/activate
pip install .

# 2. Authenticate with your existing AWS CLI / IAM Identity Center profile
aws sso login --profile my-profile
aws sts get-caller-identity --profile my-profile

# 3. Verify active AWS identity & read-only permissions locally
aws-clarity doctor --profile my-profile

# 4. Run a local read-only scan (9 zero-request-charge services by default)
aws-clarity scan --profile my-profile --output aws-clarity-report.json

# Optional: include S3 bucket configuration checks (prompts for cost consent)
aws-clarity scan --profile my-profile --include-s3-checks --output aws-clarity-report.json
```

Then open the AWS Clarity website (or run `cd frontend && npm run dev` locally) and click **Import Assessment Report (.json)**—or click **Explore Demo** to inspect a static synthetic sample account with zero AWS credentials.

---

## Documentation

| Document | Description |
| --- | --- |
| [Getting Started & Installation](./docs/GETTING_STARTED.md) | Local CLI install, AWS SSO/profile usage, `doctor`/`scan`/`policy`, Scan Diff, and team workflow |
| [IAM Permissions](./docs/IAM_PERMISSIONS.md) | Exact 28 zero-cost default actions & 6 optional S3 actions (action-by-action purpose and cost) |
| [Supported Services & Rules](./docs/SUPPORTED_SERVICES_AND_RULES.md) | 10 AWS services, 17 resource types, 43 deterministic rules, health score formula, and limitations |
| [Security & Privacy Architecture](./docs/SECURITY_AND_PRIVACY.md) | Network behaviour, CSP `connect-src 'none'`, import validation, sanitized sharing, and honest boundaries |
| [Cost Transparency](./docs/COST_TRANSPARENCY.md) | Verified \$0 static hosting options & full customer-side AWS API pricing audit |
| [Troubleshooting](./docs/TROUBLESHOOTING.md) | SSO tokens, missing permissions, optional S3 checks, and report import errors |
| [Infrastructure Migration Plan](./docs/INFRASTRUCTURE_MIGRATION.md) | Safe decommissioning plan for legacy hosted Lambda/API Gateway/DynamoDB infrastructure |
| [Security Policy](./SECURITY.md) | Private vulnerability reporting & release checksum verification |

---

## Local Development & Verification

### Backend / Local CLI Tests
```bash
pip install -r backend/requirements.txt
python3 -m unittest discover -s backend -p "test_*.py" -v
```

### Frontend Lint, Production Build & Invariant Checks
```bash
cd frontend
npm ci
npm run lint -- --max-warnings 0
npm run build
node scripts/verify-frontend-invariants.mjs
```

### Build Local Release Archive & SHA-256 Checksums (No Publishing)
```bash
bash scripts/build-release-artifacts.sh
```

---

## Project Structure

```text
aws-clarity/
├── pyproject.toml                   # Installable `aws-clarity` CLI package (pinned boto3/botocore)
├── SECURITY.md                      # Vulnerability reporting & checksum verification
├── scripts/
│   └── build-release-artifacts.sh   # Reproducible local release tarball + SHA256SUMS.txt
├── docs/                            # Complete user, security, cost, permissions & migration docs
├── backend/
│   ├── aws_clarity_cli.py           # Local CLI: `doctor`, `scan`, `policy`, `version`
│   ├── local_engine.py              # Local-first engine reusing shared collectors & rules
│   ├── scanner/                     # 10-service collectors + 43-rule deterministic misconfig engine
│   ├── test_local_cli.py            # Local CLI, profile/SSO, optional S3 consent & privacy tests
│   ├── test_detection_coverage.py   # Scope, accuracy, pagination & IAM policy parity tests
│   └── lambda_handler.py            # Legacy hosted Lambda handler (disabled by default in infra/)
├── frontend/
│   ├── vite.config.js               # Production strict CSP (`connect-src 'none'`) plugin
│   ├── scripts/verify-frontend-invariants.mjs # Privacy, import, sanitization, CSP & scope checks
│   └── src/
│       ├── pages/SetupScreen.jsx    # Privacy-first landing, report importer, Getting Started & policy
│       ├── pages/DashboardScreen.jsx # Dashboard, local Scan Diff, full & sanitized JSON/CSV exports
│       ├── components/              # TopBar, ResourceTable, DetailDrawer, Coverage/Score/Checks/Trust modals
│       └── utils/                   # reportImporter.js, reportSanitizer.js, constants.js, securityScore.js
└── infra/                           # Legacy hosted Terraform (`scans_enabled = false` default; see migration guide)
```

---

## Author & Feedback

Built by **[David Danso](https://www.linkedin.com/in/david-danso/)** — AWS Cloud Engineer.

- [Report a Bug](https://github.com/DavidDanso/aws-clarity/issues/new?template=bug_report.md&title=[Bug])
- [Request a Feature](https://github.com/DavidDanso/aws-clarity/issues/new?template=feature_request.md&title=[Feature])
- [Report a Security Vulnerability](https://github.com/DavidDanso/aws-clarity/security/advisories/new)
