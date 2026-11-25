# Changelog

All notable changes to AWS Clarity are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [1.1.0] — Unreleased (Prepared on `hardening/unknown-env-beta-readiness`)

### Versioning Rationale (`1.0.0` → `1.1.0`)
- Existing tag `v1.0.0` points to commit `5917933`, which predates the UI/rule updates on `main` (`64671bd`) and all Phase 1–4 security, correctness, browser, and supply-chain hardening work.
- **`1.1.0` (MINOR)** is recommended over `1.0.1` because this release introduces new user-facing CLI flags (`--allow-root`, `--yes`), interactive pre-scan confirmation, a client-layer API allowlist, a new CloudFormation read-only role template, new report fields (`impact`, `finding_counts`), and heuristic rule reclassifications—while keeping the `aws-clarity-report/v1` schema and core read-only CLI workflow backwards-compatible.
- **Automation note:** Non-interactive scripts invoking `aws-clarity scan` must now pass `--yes` (`-y`) to confirm the pre-scan identity and scope summary.

### Security (Phase 1)
- Added `docs/THREAT_MODEL.md` covering 13 unknown-environment threats with Enforced / Recommended / Residual Risk separation.
- Added default AWS account root refusal (`RootIdentityBlockedError`, exit code `2`) in both `doctor` and `scan`, with explicit `--allow-root` override.
- Added name-only admin heuristic warning (`WARNING (name heuristic only)`) making zero extra IAM calls.
- Added transparent pre-scan confirmation prompt (`[y/N]` default No; `--yes` for non-interactive shells) with masked Account IDs (`********9012`) and Caller ARNs.
- Added strict credential string redaction (`redact_credential_strings`) and explicit `ProfileNotFound` refusal (no silent credential fallback).
- Added authoritative client-layer AWS API operation allowlist (`backend/api_guard.py`) enforcing exact 28 default / 34 optional-S3 read-only operations via botocore `before-call` hooks and proxy interception, with isolated `sts:AssumeRole` only for `--role-arn`.
- Implemented field-level data minimization across all 15 collectors and post-evaluation pruning of raw IAM inline/trust policy documents.
- Added customer-deployable read-only IAM role CloudFormation template (`infra/aws-clarity-readonly-role.yaml`) with `TrustedPrincipalArn`, optional `ExternalId`, and `IncludeS3Checks`.
- Added visible read-only role callout (outside collapsed sections) and highlighted `--include-s3-checks` badge in onboarding Step 2.

### Scanner Correctness & Remediation Safety (Phase 2)
- Fixed Security Group checks (`SG-002`, `SG-003`, `SG-004`) to handle omitted TCP/UDP port ranges (`0–65535`), numeric protocols (`"6"`, `"17"`), and avoid false positives on UDP-only SSH/DB rules.
- Hardened IAM rules (`IAM-001`, `IAM-002`, `IAM-005`, `IAM-006`, `IAM-008`, `IAM-010`, `IAM-011`) for case-insensitive `iam:*` / service wildcards, `NotResource`, list-wrapped `Principal: {"AWS": ["*"]}`, multi-partition/STS account extraction, rejection of negated/`Null`/`*IfExists` condition bypasses, fail-closed `IAM-009` when policy inspection fails, and `CHECK_FAILED` on unparseable access key dates.
- Fixed `VPC-001` to mark `CHECK_FAILED` instead of false `HEALTHY` when EC2 or RDS discovery failed in that region.
- Fixed `_parse_datetime` crash on naive ISO timestamps and non-fractional timezone offsets.
- Scoped `CT-000` missing-trail advisory strictly to clean all-regions scans (preventing false alarms on single-region subsets) and accounted for critical advisories in health score calculation.
- Added consequences & dependencies (`impact`) guidance to all 43 rules and `CT-000`, rendered in `DetailDrawer` and `DashboardScreen`.
- Fixed `evaluateCheckStatus` so failed collectors with 0 resources or partial failures report `CHECK_FAILED` rather than `No resources in account` or `PASSED`.
- Documented heuristic rule reclassifications (`S3-004`, `EC2-001`, `DDB-002` → `INFO`; exact counts: `13 CRITICAL / 20 WARNING / 3 UNUSED / 7 INFO`).

### Browser & Report Security (Phase 3)
- Hardened `reportImporter.js` with separator/case-normalized credential key detection, secret/STS-token value blocking, strict `status`/`severity` validation, unassessed `HEALTHY`→`INCOMPLETE` normalization, resource deduplication, filename sanitization, and pre-read 25 MB size checks.
- Hardened `reportSanitizer.js` to redact all finding text, `impact`, `account_advisories`, assessment reasons, scanner status reasons, IAM access key IDs, AWS resource IDs, and IPv6 addresses, fixing ARN-before-account-ID redaction ordering.
- Hardened `neutralizeCsvCell()` against leading whitespace/newline formula prefixes across every CSV column.
- Hardened `scanComparison.js` with cross-account comparison refusal, `unverified` tracking for disappeared/incomplete/skipped-optional findings (never falsely marked resolved), region-aware fallback IDs, and score-delta withholding.
- Added explicit best-effort redaction disclaimer and private-only Full Export warnings in the Export Modal.
- Added reproducible local production-build headless Chrome verifier (`frontend/scripts/verify-phase3-browser.mjs`).

### Release Integrity, Supply-Chain & Hosting (Phase 4)
- Fixed `pyproject.toml` (`py-modules` now includes `api_guard`) and `scripts/build-release-artifacts.sh` (dynamic version from `pyproject.toml`, includes `backend/api_guard.py`, `LICENSE`, `CHANGELOG.md`).
- Hardened `.github/workflows/ci-release.yml` (branch trigger, tag-to-version check, installed-wheel flag verification, all Phase 1–3 frontend checks, and `actions/attest-build-provenance` build provenance attestations).
- Added `.github/workflows/publish-pypi.yml` for OIDC PyPI Trusted Publishing gated on published releases and manual `pypi` environment approval.
- Pinned GitHub Actions in `.github/workflows/pages.yml` to full commit SHAs and added Phase 1–3 checks to `pages.yml` and `deploy.yml`.
- Prepared HTTP security response headers (`aws_cloudfront_response_headers_policy`) in `infra/cloudfront.tf` (not yet applied to AWS).
- Added independent audit guide (`docs/AUDIT.md`) and refined cost/security disclosures (`docs/COST_TRANSPARENCY.md`, `SECURITY.md`).

---

## [1.0.0] — 2026-11-22 (Published Tag `5917933`)

- Initial local-first, read-only `aws-clarity` Python CLI (`doctor`, `scan`, `policy`, `version`), 10 AWS services, 17 resource types, 43 deterministic rules + `CT-000` advisory, static React report viewer with production `<meta>` CSP `connect-src 'none'`, local Scan Diff, and full/sanitized JSON & CSV exports.
- Note: Published `v1.0.0` artifacts on GitHub Releases were built from commit `5917933` and do **not** include the post-tag UI/rule commits on `main` (`c248e94`, `0d943d8`, `64671bd`) or Phases 1–4 hardening.
