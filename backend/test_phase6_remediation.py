"""
Phase 6 Remediation Regression Tests:
1. Botocore endpoint_resolver deprecation removal in backend/utils.py
2. Release version / install URL / artifact filename parity against pyproject.toml
3. Frontend WCAG contrast & keyboard-accessible scrollable modal guardrails
"""

import ast
import os
import re
import sys
import unittest
import warnings
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import utils  # noqa: E402


def _read_pyproject_metadata():
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    name_m = re.search(r'(?ms)^\[project\].*?^\s*name\s*=\s*"([^"]+)"', text)
    ver_m = re.search(r'(?ms)^\[project\].*?^\s*version\s*=\s*"([^"]+)"', text)
    if not name_m or not ver_m:
        raise AssertionError("Unable to parse [project] name/version from pyproject.toml")
    return name_m.group(1), ver_m.group(1)


class TestBotocoreDeprecationRemediation(unittest.TestCase):
    def test_utils_does_not_call_deprecated_internal_endpoint_resolver(self):
        src = (BACKEND_DIR / "utils.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotEqual(
                    node.func.attr,
                    "get_component",
                    "backend/utils.py must not invoke deprecated botocore get_component()",
                )
        self.assertNotIn("_SHARED_STATIC_BC", src)
        self.assertNotIn("_SHARED_ENDPOINT_RESOLVER", src)

    def test_build_isolated_session_emits_no_deprecation_warnings(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            sess_a = utils.build_isolated_session(
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key="synthetic-secret-a",
                session_token="synthetic-token-a",
                region_name="us-east-1",
            )
            sess_b = utils.build_isolated_session(
                access_key_id="AKIAEXAMPLE000000002",
                secret_access_key="synthetic-secret-b",
                session_token="synthetic-token-b",
                region_name="eu-west-1",
            )

        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        self.assertEqual(
            dep_warnings,
            [],
            f"Unexpected DeprecationWarning(s): {[str(w.message) for w in dep_warnings]}",
        )
        creds_a = sess_a.get_credentials().get_frozen_credentials()
        creds_b = sess_b.get_credentials().get_frozen_credentials()
        self.assertEqual(sess_a.region_name, "us-east-1")
        self.assertEqual(sess_b.region_name, "eu-west-1")
        self.assertEqual(creds_a.access_key, "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(creds_b.access_key, "AKIAEXAMPLE000000002")
        self.assertNotEqual(creds_a.access_key, creds_b.access_key)
        self.assertNotEqual(creds_a.token, creds_b.token)


class TestReleaseVersionAndUrlParity(unittest.TestCase):
    """Fails if frontend or documentation release URLs / artifact filenames drift from pyproject.toml."""

    def test_frontend_and_docs_match_pyproject_version_and_artifacts(self):
        pkg_name, version = _read_pyproject_metadata()
        self.assertEqual(pkg_name, "aws-clarity")

        norm_name = pkg_name.replace("-", "_")
        expected_wheel = f"{norm_name}-{version}-py3-none-any.whl"
        expected_sdist = f"{norm_name}-{version}.tar.gz"
        expected_local_tar = f"{pkg_name}-local-{version}.tar.gz"
        expected_tag = f"v{version}"
        expected_release_url = f"https://github.com/DavidDanso/aws-clarity/releases/tag/{expected_tag}"
        expected_download_base = f"https://github.com/DavidDanso/aws-clarity/releases/download/{expected_tag}"
        expected_asset_urls = [
            f"{expected_download_base}/{expected_wheel}",
            f"{expected_download_base}/{expected_sdist}",
            f"{expected_download_base}/{expected_local_tar}",
            f"{expected_download_base}/SHA256SUMS.txt",
        ]

        # 1. Frontend SetupScreen.jsx must match pyproject.toml version, link to published v1.1.0 release, and not show stale unpublished notice
        setup_src = (REPO_ROOT / "frontend" / "src" / "pages" / "SetupScreen.jsx").read_text(encoding="utf-8")
        self.assertIn(f'const RELEASE_VERSION = "{version}";', setup_src)
        self.assertIn("https://github.com/DavidDanso/aws-clarity/releases/tag/v${RELEASE_VERSION}", setup_src)
        self.assertIn("aws_clarity-${RELEASE_VERSION}-py3-none-any.whl", setup_src)
        self.assertIn("aws_clarity-{RELEASE_VERSION}.tar.gz", setup_src)
        self.assertIn("aws-clarity-local-{RELEASE_VERSION}.tar.gz", setup_src)
        self.assertIn("SHA256SUMS.txt", setup_src)
        self.assertNotIn("/releases/latest", setup_src)
        self.assertNotIn("not yet published", setup_src.lower())
        self.assertNotIn("pending publication", setup_src.lower())

        # 2. docs/GETTING_STARTED.md and README.md must reflect published v1.1.0 release accurately
        getting_started = (REPO_ROOT / "docs" / "GETTING_STARTED.md").read_text(encoding="utf-8")
        self.assertIn(expected_release_url, getting_started)
        for url in expected_asset_urls:
            self.assertIn(url, getting_started)
        self.assertIn(f"aws-clarity {version}", getting_started)
        self.assertNotIn("/releases/latest", getting_started)
        self.assertNotIn("not yet published", getting_started.lower())
        self.assertNotIn("pending publication", getting_started.lower())

        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(expected_release_url, readme)
        self.assertNotIn("not yet published", readme.lower())

        # 3. docs/V1.1.0_INSTALLATION_PREPARATION.md must match pyproject.toml version and prepared URLs
        prep_doc = (REPO_ROOT / "docs" / "V1.1.0_INSTALLATION_PREPARATION.md").read_text(encoding="utf-8")
        self.assertIn(expected_release_url, prep_doc)
        for url in expected_asset_urls:
            self.assertIn(url, prep_doc)
        self.assertIn(f"`{pkg_name}`", prep_doc)
        self.assertIn(f"`{version}`", prep_doc)
        self.assertNotIn("https://github.com/DavidDanso/aws-clarity/releases/latest", prep_doc)
        self.assertNotIn("https://pypi.org/project/aws-clarity", prep_doc)

        # 4. Ensure no stale mismatched aws_clarity-<other>-py3-none-any.whl references in SetupScreen or prep doc
        for label, content in [("SetupScreen.jsx", setup_src), ("V1.1.0_INSTALLATION_PREPARATION.md", prep_doc)]:
            found_wheels = re.findall(r"aws_clarity-([0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl", content)
            for found_ver in found_wheels:
                self.assertEqual(
                    found_ver,
                    version,
                    f"{label} references wheel version {found_ver} != pyproject.toml {version}",
                )


class TestFrontendAccessibilityGuardrails(unittest.TestCase):
    def test_no_low_contrast_slate_500_or_teal_600_regressions(self):
        frontend_src = REPO_ROOT / "frontend" / "src"
        for path in frontend_src.rglob("*.jsx"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(
                "text-slate-500",
                text,
                f"{path.relative_to(REPO_ROOT)} reintroduces low-contrast text-slate-500",
            )
            self.assertNotIn(
                "bg-teal-600",
                text,
                f"{path.relative_to(REPO_ROOT)} reintroduces low-contrast bg-teal-600",
            )

    def test_scrollable_modals_have_keyboard_focusable_regions(self):
        modal_dir = REPO_ROOT / "frontend" / "src" / "components"
        for modal_file in [
            "CoverageModal.jsx",
            "ChecksCatalogModal.jsx",
            "ScoreModal.jsx",
            "TrustModal.jsx",
        ]:
            text = (modal_dir / modal_file).read_text(encoding="utf-8")
            self.assertIn("tabIndex={0}", text, f"{modal_file} missing keyboard-focusable scrollable region")
            self.assertIn('role="region"', text, f"{modal_file} missing region role on scrollable body")


class TestPyPIWorkflowAndSecurityDisclosures(unittest.TestCase):
    def test_publish_pypi_workflow_is_controlled_oidc_and_reuses_verified_release_assets(self):
        wf = (REPO_ROOT / ".github" / "workflows" / "publish-pypi.yml").read_text(encoding="utf-8")
        # Must NOT trigger automatically on release events
        self.assertNotIn("types: [published]", wf)
        self.assertIn("workflow_dispatch:", wf)
        self.assertIn("gh release download", wf)
        self.assertIn("sha256sum -c", wf)
        self.assertIn("gh attestation verify", wf)
        self.assertIn("name: pypi", wf)
        self.assertIn("id-token: write", wf)
        self.assertIn("pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086", wf)
        self.assertNotIn("python -m build", wf)

    def test_security_assurance_disclosure_present_across_frontend_and_docs(self):
        targets = [
            REPO_ROOT / "frontend" / "src" / "pages" / "SetupScreen.jsx",
            REPO_ROOT / "frontend" / "src" / "components" / "TrustModal.jsx",
            REPO_ROOT / "README.md",
            REPO_ROOT / "SECURITY.md",
            REPO_ROOT / "docs" / "GETTING_STARTED.md",
            REPO_ROOT / "docs" / "SUPPORTED_SERVICES_AND_RULES.md",
        ]
        for path in targets:
            flat = " ".join(path.read_text(encoding="utf-8").split())
            self.assertIn("Security Assurance and Limitations", flat, f"Missing heading in {path.name}")
            self.assertIn("independent third-party penetration test", flat.lower(), f"Missing disclosure in {path.name}")
            self.assertIn("formal security certification", flat.lower(), f"Missing certification disclosure in {path.name}")


if __name__ == "__main__":
    unittest.main()
