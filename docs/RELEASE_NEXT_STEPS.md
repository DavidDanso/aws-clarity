# AWS Clarity `v1.1.0` Release Next Steps

This document lists the exact remaining actions required to move AWS Clarity from local Phase 6 remediation to a verified `v1.1.0` release and live hardened website. **None of the publication, deployment, AWS, or GitHub settings steps below have been executed yet; each requires explicit owner approval.**

---

## Stage 1 — Owner Review & Branch CI (Next Immediate Milestone)

### Required Owner Approval
- Approve pushing `hardening/unknown-env-beta-readiness` to `origin` (`DavidDanso/aws-clarity`).

### Commands & Verification
1. Verify local clean tree and commit hash:
   ```bash
   git status --short
   git log -n 5 --oneline
   ```
2. Push **only** the hardening branch (triggers `.github/workflows/ci-release.yml` CI jobs only — does **not** publish releases, PyPI, or deploy AWS):
   ```bash
   git push origin hardening/unknown-env-beta-readiness
   ```
3. Confirm **100% pass with 0 cancelled/skipped jobs** on the exact final commit SHA across:
   - All **12 `scanner-matrix` jobs** (`ubuntu-latest`, `macos-latest`, `windows-latest` × Python `3.10`, `3.11`, `3.12`, `3.13`), including `test_phase6_remediation.py` and `pip-audit`.
   - `frontend-verify` (`npm ci`, `npm audit`, ESLint `--max-warnings 0`, Vite production build, static security/canary/correctness checks).

---

## Stage 2 — Owner-Led Security & Repository Hygiene Checks

Before promoting `v1.1.0` publicly:

1. **Run `gitleaks` (or enable GitHub Secret Scanning + Push Protection)** in `DavidDanso/aws-clarity` repository settings so dedicated third-party secret scanning moves from `NOT VERIFIED` to `PASS`.
2. **Confirm GitHub Private Vulnerability Reporting is enabled** in **Settings → Code security** so `https://github.com/DavidDanso/aws-clarity/security/advisories/new` works for external reporters.
3. **Review owner AWS IAM key hygiene** (e.g., rotating or retiring the 252-day-old `danso` IAM user access key in favor of IAM Identity Center / GitHub OIDC for `deploy.yml`).

---

## Stage 3 — Merge to `main` & Publish `v1.1.0` Release

### Required Owner Approval
- Approve merging `hardening/unknown-env-beta-readiness` into `main` and pushing annotated tag `v1.1.0`.

### Publication Procedure
1. Open and merge a Pull Request from `hardening/unknown-env-beta-readiness` into `main` (prefer a regular merge or squash-with-clean-history after all branch CI checks pass).
2. Pull updated `main` locally and verify `pyproject.toml` version is `1.1.0`:
   ```bash
   git checkout main
   git pull origin main
   ```
3. Create and push tag `v1.1.0` (this triggers `.github/workflows/ci-release.yml` → `scanner-matrix` + `frontend-verify` → `publish-release` with SLSA provenance attestation):
   ```bash
   git tag -a v1.1.0 -m "AWS Clarity v1.1.0 (Local-First Hardened Release)"
   git push origin v1.1.0
   ```
4. Wait for the `publish-release` workflow job to succeed and confirm the release page and all 4 assets are live:
   - `https://github.com/DavidDanso/aws-clarity/releases/tag/v1.1.0`
   - `https://github.com/DavidDanso/aws-clarity/releases/download/v1.1.0/aws_clarity-1.1.0-py3-none-any.whl`
   - `https://github.com/DavidDanso/aws-clarity/releases/download/v1.1.0/aws_clarity-1.1.0.tar.gz`
   - `https://github.com/DavidDanso/aws-clarity/releases/download/v1.1.0/aws-clarity-local-1.1.0.tar.gz`
   - `https://github.com/DavidDanso/aws-clarity/releases/download/v1.1.0/SHA256SUMS.txt`
5. *(Optional, separate owner approval)* Update `SetupScreen.jsx` in a small post-release follow-up PR (`v1.1.0` live status) only **after** the `v1.1.0` URLs above return `HTTP 200` and pass checksum/attestation verification.

---

## Stage 4 — Deploy Hardened Frontend & HTTP Security Headers

### Required Owner Approval
- Approve deploying the static frontend and applying `infra/` Terraform changes (CloudFront Response Headers Policy + S3 static site sync + CloudFront invalidation).

### CloudFront / S3 Deployment Procedure
1. Review Terraform plan carefully before applying (via `.github/workflows/deploy.yml` manual `workflow_dispatch` with `action: deploy`, or local `terraform -chdir=infra plan` + owner-approved `apply`):
   - Confirms CloudFront attaches the security headers policy (`Content-Security-Policy` with `connect-src 'none'`, `frame-ancestors 'none'`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`).
   - Syncs freshly built `frontend/dist/` to the S3 origin bucket with `--delete`.
   - Invalidates `/*` on the CloudFront distribution.
2. *(Optional)* Enable GitHub Pages (`.github/workflows/pages.yml`) if hosting on GitHub Pages in addition to CloudFront.

---

## Stage 5 — Independent Live Verification (All 15 Mandatory Gates)

Do **not** announce or promote AWS Clarity as ready for public beta until an independent live verification pass confirms:

1. **Live Release Integrity:**
   - `curl -fLO` downloads `aws_clarity-1.1.0-py3-none-any.whl` and `SHA256SUMS.txt` from `releases/download/v1.1.0/...` with `HTTP 200`.
   - `shasum -a 256 -c --ignore-missing SHA256SUMS.txt` passes (`OK`).
   - `gh attestation verify aws_clarity-1.1.0-py3-none-any.whl --repo DavidDanso/aws-clarity` passes.
   - Clean venv install of the downloaded live wheel passes `aws-clarity version`, `aws-clarity policy --zero-cost-only` (28 actions), `aws-clarity scan --help` (`--yes`, `--allow-root`), and root-block test.
2. **Live Website & HTTP Security Headers:**
   - `curl -sSI https://<live-cloudfront-or-custom-domain>/` returns `HTTP 200` with **server-enforced HTTP headers**:
     - `Content-Security-Policy` (including `connect-src 'none'` and `frame-ancestors 'none'`)
     - `Strict-Transport-Security`
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: DENY`
     - `Referrer-Policy: no-referrer`
     - `Permissions-Policy`
   - Live browser check confirms the updated hardened frontend bundle is served (not the stale pre-hardening `v1.0.0` page), demo mode works, offline local report import works with zero network requests, and `axe-core` reports 0 WCAG 2 AA violations.
3. **Repository & Security Settings:**
   - `gitleaks` / GitHub Secret Scanning verified clean.
   - GitHub Private Vulnerability Reporting verified active.
