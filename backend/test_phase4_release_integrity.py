"""Phase 4 Release Integrity, Supply-Chain & Hosting Security Verification Tests.

Validates local packaging metadata, build script parity, GitHub Actions workflow
hardening (SHA pinning, PyPI Trusted Publishing gating, attestation), CloudFront
HTTP response headers policy consistency, and independent audit documentation.
Zero network or AWS calls.
"""

import os
import re
import sys
import unittest

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None

sys.path.insert(0, os.path.dirname(__file__))

import local_engine

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _parse_pyproject_minimal(text: str) -> dict:
    """Minimal stdlib-only TOML subset parser for pyproject.toml on Python 3.10.

    Supports dotted [table] headers, string/inline-table values, and single-line or
    multi-line string arrays — enough to validate pyproject.toml without external
    dependencies when neither tomllib (3.11+) nor tomli is installed.
    """
    root: dict = {}
    current = root
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i].split("#", 1)[0].strip()
        i += 1
        if not raw:
            continue
        if raw.startswith("[") and raw.endswith("]"):
            header = raw[1:-1].strip()
            current = root
            for part in header.split("."):
                part = part.strip().strip('"').strip("'")
                current = current.setdefault(part, {})
            continue
        if "=" not in raw:
            continue
        key, val = [s.strip() for s in raw.split("=", 1)]
        key = key.strip('"').strip("'")
        if val.startswith("["):
            buf = val
            while buf.count("[") > buf.count("]") and i < len(lines):
                buf += " " + lines[i].split("#", 1)[0].strip()
                i += 1
            current[key] = re.findall(r'"([^"]*)"', buf)
        elif val.startswith("{"):
            pairs = re.findall(r'([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"', val)
            current[key] = dict(pairs)
        elif val.startswith('"') and val.endswith('"'):
            current[key] = val[1:-1]
        elif val.startswith("'") and val.endswith("'"):
            current[key] = val[1:-1]
        else:
            current[key] = val
    return root


def _load_pyproject(path: str) -> dict:
    with open(path, "rb") as fh:
        raw = fh.read()
    if tomllib is not None:
        return tomllib.loads(raw.decode("utf-8"))
    return _parse_pyproject_minimal(raw.decode("utf-8"))


class TestPhase4ReleaseIntegrityAndSupplyChain(unittest.TestCase):
    def test_pyproject_includes_all_runtime_modules_and_matches_cli_version(self):
        pyproject_path = os.path.join(REPO_ROOT, "pyproject.toml")
        data = _load_pyproject(pyproject_path)
        # Also verify the Python 3.10 fallback parser agrees with tomllib on every critical field
        with open(pyproject_path, encoding="utf-8") as fh:
            fallback = _parse_pyproject_minimal(fh.read())
        self.assertEqual(fallback["project"]["version"], data["project"]["version"])
        self.assertEqual(
            set(fallback["tool"]["setuptools"]["py-modules"]),
            set(data["tool"]["setuptools"]["py-modules"]),
        )

        project = data["project"]
        self.assertEqual(project["name"], "aws-clarity")
        self.assertEqual(project["version"], local_engine.CLI_VERSION)
        self.assertEqual(project["requires-python"], ">=3.10")
        self.assertEqual(project["scripts"]["aws-clarity"], "aws_clarity_cli:main")

        py_modules = set(data["tool"]["setuptools"]["py-modules"])
        required_modules = {"api_guard", "aws_clarity_cli", "local_engine", "lambda_handler", "utils", "exceptions"}
        self.assertTrue(required_modules.issubset(py_modules), f"Missing py-modules: {required_modules - py_modules}")
        self.assertIn("scanner", data["tool"]["setuptools"]["packages"])
        self.assertIn("LICENSE", data["tool"]["setuptools"].get("license-files", []))

        # Verify boto3/botocore versions match backend/requirements.txt
        with open(os.path.join(REPO_ROOT, "backend", "requirements.txt"), encoding="utf-8") as fh:
            req_lines = [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]
        self.assertEqual(sorted(project["dependencies"]), sorted(req_lines))

    def test_release_build_script_includes_api_guard_license_and_dynamic_version(self):
        script_path = os.path.join(REPO_ROOT, "scripts", "build-release-artifacts.sh")
        with open(script_path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("pyproject.toml", src, "Build script must derive version dynamically from pyproject.toml")
        self.assertIn("backend/api_guard.py", src, "Standalone tarball must include backend/api_guard.py")
        self.assertIn("LICENSE", src, "Standalone tarball must include LICENSE")
        self.assertIn("SHA256SUMS.txt", src)
        self.assertNotIn('VERSION="1.0.0"', src, "Build script must not hardcode stale VERSION=1.0.0")

    def test_github_workflows_pin_all_actions_by_sha_and_gate_publishing(self):
        wf_dir = os.path.join(REPO_ROOT, ".github", "workflows")
        sha_uses_re = re.compile(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([A-Za-z0-9_./-]+)")
        hex40_re = re.compile(r"^[0-9a-f]{40}$")

        for fname in ("ci-release.yml", "pages.yml", "deploy.yml", "publish-pypi.yml"):
            fpath = os.path.join(wf_dir, fname)
            self.assertTrue(os.path.isfile(fpath), f"Expected workflow missing: {fname}")
            with open(fpath, encoding="utf-8") as fh:
                content = fh.read()
            matches = sha_uses_re.findall(content)
            self.assertGreater(len(matches), 0, f"No actions found in {fname}")
            for action, ref in matches:
                self.assertRegex(
                    ref,
                    hex40_re,
                    f"Action {action}@{ref} in {fname} must be pinned to a full 40-char commit SHA",
                )

        # CI workflow supports hardening branch, all Phase 1-3 scripts, tag parity, and provenance attestation
        with open(os.path.join(wf_dir, "ci-release.yml"), encoding="utf-8") as fh:
            ci = fh.read()
        self.assertIn("hardening/unknown-env-beta-readiness", ci)
        self.assertIn("workflow_dispatch:", ci)
        self.assertIn("actions/attest-build-provenance@", ci)
        self.assertIn("verify-phase1-canary.mjs", ci)
        self.assertIn("verify-phase2-correctness.mjs", ci)
        self.assertIn("verify-phase3-security.mjs", ci)
        self.assertIn("--allow-root", ci)
        self.assertIn("--yes", ci)

        # PyPI workflow uses OIDC Trusted Publishing only (never on push or pull_request; no API token secret)
        with open(os.path.join(wf_dir, "publish-pypi.yml"), encoding="utf-8") as fh:
            pypi = fh.read()
        self.assertIn("pypa/gh-action-pypi-publish@", pypi)
        self.assertIn("id-token: write", pypi)
        self.assertIn("name: pypi", pypi)
        self.assertNotIn("PYPI_API_TOKEN", pypi)
        self.assertNotRegex(pypi, r"^\s*push:\s*$", "PyPI publish must never trigger on branch push")
        self.assertNotRegex(pypi, r"^\s*pull_request:\s*$", "PyPI publish must never trigger on pull_request")

    def test_cloudfront_response_headers_policy_matches_csp_and_avoids_premature_hsts_preload(self):
        with open(os.path.join(REPO_ROOT, "infra", "cloudfront.tf"), encoding="utf-8") as fh:
            cf = fh.read()
        with open(os.path.join(REPO_ROOT, "frontend", "vite.config.js"), encoding="utf-8") as fh:
            vite = fh.read()

        self.assertIn('resource "aws_cloudfront_response_headers_policy" "security_headers"', cf)
        self.assertIn("response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id", cf)

        for required_directive in (
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'none'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        ):
            self.assertIn(required_directive, vite, f"vite.config.js meta CSP missing {required_directive}")
            self.assertIn(required_directive, cf, f"CloudFront HTTP CSP missing {required_directive}")

        self.assertIn("frame-ancestors 'none'", cf)
        self.assertIn('frame_option = "DENY"', cf)
        self.assertIn("content_type_options", cf)
        self.assertIn('referrer_policy = "no-referrer"', cf)
        self.assertIn('header   = "Permissions-Policy"', cf)
        # HSTS preload and include_subdomains must remain false until a dedicated custom domain is verified
        self.assertIn("include_subdomains         = false", cf)
        self.assertIn("preload                    = false", cf)

    def test_audit_changelog_security_and_reproducible_browser_script_exist_with_valid_references(self):
        for rel in (
            "docs/AUDIT.md",
            "CHANGELOG.md",
            "SECURITY.md",
            "docs/COST_TRANSPARENCY.md",
            "frontend/scripts/verify-phase3-browser.mjs",
        ):
            full = os.path.join(REPO_ROOT, rel)
            self.assertTrue(os.path.isfile(full), f"Required Phase 4 file missing: {rel}")

        with open(os.path.join(REPO_ROOT, "docs", "AUDIT.md"), encoding="utf-8") as fh:
            audit_md = fh.read()
        for ref_path in (
            "backend/api_guard.py",
            "backend/local_engine.py",
            "backend/aws_clarity_cli.py",
            "backend/scanner/misconfig.py",
            "frontend/src/utils/reportImporter.js",
            "frontend/src/utils/reportSanitizer.js",
            "frontend/scripts/verify-phase3-browser.mjs",
            "infra/aws-clarity-readonly-role.yaml",
            "infra/cloudfront.tf",
        ):
            self.assertIn(ref_path, audit_md)
            self.assertTrue(os.path.exists(os.path.join(REPO_ROOT, ref_path)), f"AUDIT.md references missing file {ref_path}")

        with open(os.path.join(REPO_ROOT, "docs", "COST_TRANSPARENCY.md"), encoding="utf-8") as fh:
            cost_md = fh.read()
        self.assertNotIn("guaranteed $0 hosting", cost_md.lower())
        self.assertNotIn("guaranteed \\$0 hosting", cost_md.lower())


if __name__ == "__main__":
    unittest.main()
