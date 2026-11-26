"""Phase 5 CLI Usability, Terminal Progress, Summary & Actionable Error Tests.

Verifies:
- Chronological non-flooding terminal progress output during local scans
- Unmistakable status markers (never green/DONE for INCOMPLETE, FAILED, or SKIPPED_OPTIONAL)
- No raw account IDs, raw caller ARNs, or secret values in ordinary progress/summary output
- Complete final scan summary (resources, severity & category counts, coverage, failed regions,
  optional S3 status, local file confirmation, configurable dashboard URL without hardcoded old CDN)
- Actionable What/Why/Next error messages for missing profile, missing creds, expired SSO, and AssumeRole
- Interactive confirmation & non-interactive --yes compatibility preserved
"""

import io
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound, TokenRetrievalError

sys.path.insert(0, os.path.dirname(__file__))

import aws_clarity_cli
import lambda_handler
import local_engine
from exceptions import AssumeRoleError


class TestPhase5CliProgressAndSummary(unittest.TestCase):
    def test_progress_callback_emits_honest_statuses_without_leaking_raw_account_id(self):
        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {
            "Account": "987654321098",
            "Arn": "arn:aws:sts::987654321098:assumed-role/ClarityReadOnly/alice",
            "UserId": "AROA123:alice",
        }
        ec2_client = MagicMock()
        ec2_client.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        session.client.side_effect = lambda svc, **kw: sts if svc == "sts" else ec2_client

        regional_patches = [
            ("ec2", "scan"), ("elastic_ip", "scan"), ("security_group", "scan"),
            ("vpcs", "scan"), ("internet_gateways", "scan"), ("nat_gateways", "scan"),
            ("lambda_functions", "scan"), ("dynamodb_tables", "scan"),
            ("ebs", "scan"), ("snapshots", "scan"),
            ("cloudwatch", "scan_alarms"), ("cloudwatch", "scan_log_groups"),
            ("cloudtrail", "scan"),
        ]
        events = []
        with ExitStack() as stack:
            for mod_name, fn_name in regional_patches:
                stack.enter_context(patch.object(getattr(lambda_handler, mod_name), fn_name, return_value=[]))
            # Force RDS failure so we verify [FAILED] / [INCOMPLETE] never renders as [DONE]
            stack.enter_context(
                patch.object(lambda_handler.rds, "scan", side_effect=RuntimeError("AccessDenied on DescribeDBInstances"))
            )
            stack.enter_context(patch.object(local_engine.iam, "scan_roles", return_value=[]))
            stack.enter_context(patch.object(local_engine.iam, "scan_users", return_value=[]))

            report = local_engine.run_local_scan(
                session,
                regions=["us-east-1"],
                include_s3_checks=False,
                progress_callback=events.append,
            )

        stages = [e["stage"] for e in events]
        self.assertEqual(stages[0], "start")
        self.assertIn("identity", stages)
        self.assertIn("regions", stages)
        self.assertIn("collect_start", stages)
        self.assertIn("collect_service", stages)
        self.assertEqual(stages[-1], "evaluate")

        rendered = "\n".join(aws_clarity_cli._format_cli_progress(e) for e in events)
        self.assertIn("********1098", rendered)
        self.assertNotIn("987654321098", rendered)
        self.assertIn("[SKIPPED]    S3", rendered)
        self.assertIn("[FAILED]     RDS", rendered)
        self.assertNotIn("[DONE]       RDS", rendered)
        self.assertNotIn("[DONE]       S3", rendered)
        self.assertEqual(report["coverage"]["status"], "INCOMPLETE")

    def test_final_scan_summary_complete_and_incomplete_and_configurable_dashboard_url(self):
        fake_session = MagicMock()
        ident = {
            "account_id": "123456789012",
            "caller_arn": "arn:aws:sts::123456789012:assumed-role/ClarityReadOnly/dev",
        }
        incomplete_report = {
            "schema_version": "aws-clarity-report/v1",
            "scanner_version": local_engine.CLI_VERSION,
            "execution_mode": "local-cli",
            "status": "INCOMPLETE",
            "partial": True,
            "account_id": "123456789012",
            "caller_arn": ident["caller_arn"],
            "regions": ["us-east-1", "eu-west-1"],
            "scan_duration_ms": 2340,
            "summary": {
                "total_resources": 7,
                "critical_issues": 1,
                "warnings": 2,
                "unused": 1,
                "info_observations": 1,
                "finding_counts": {"critical": 1, "warning": 2, "unused": 1, "info": 1},
                "security_risks": 2,
                "operational_concerns": 1,
                "potential_cost_waste": 2,
            },
            "coverage": {
                "status": "INCOMPLETE",
                "regions_scanned": ["us-east-1", "eu-west-1"],
                "regions_failed": ["eu-west-1"],
                "services_skipped_optional": ["S3"],
                "failures": [{"service": "RDS", "region": "eu-west-1", "reason": "AccessDenied"}],
            },
            "resources": {"vpcs": []},
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "aws-clarity-report.json")
            stderr_buf = io.StringIO()
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AWS_CLARITY_DASHBOARD_URL", None)
                with patch("aws_clarity_cli.create_local_session", return_value=fake_session), \
                     patch("aws_clarity_cli.verify_identity", return_value=ident), \
                     patch("aws_clarity_cli.run_local_scan", return_value=incomplete_report), \
                     redirect_stderr(stderr_buf):
                    rc = aws_clarity_cli.main(["scan", "--yes", "--output", out_path])

            self.assertEqual(rc, 0)
            err = stderr_buf.getvalue()
            self.assertIn("INCOMPLETE — coverage gaps detected", err)
            self.assertIn("Discovered Resources: 7", err)
            self.assertIn("Critical: 1 | Warning: 2 | Unused: 1 | Info: 1", err)
            self.assertIn("Security Risk: 2 | Operational Concern: 1 | Potential Cost Waste: 2", err)
            self.assertIn("Failed Regions      : eu-west-1", err)
            self.assertIn("SKIPPED_OPTIONAL (not evaluated; not marked healthy)", err)
            self.assertIn("Next: open the AWS Clarity dashboard and import", err)
            self.assertNotIn("dyw8yx5pnnt0t.cloudfront.net", err)
            self.assertNotIn("dmydkbmdw1lzr.cloudfront.net", err)
            self.assertNotIn("123456789012", err)

            # With AWS_CLARITY_DASHBOARD_URL explicitly configured (https:// only)
            stderr_cfg = io.StringIO()
            with patch.dict(os.environ, {"AWS_CLARITY_DASHBOARD_URL": "https://dashboard.example.internal/"}, clear=False):
                with patch("aws_clarity_cli.create_local_session", return_value=fake_session), \
                     patch("aws_clarity_cli.verify_identity", return_value=ident), \
                     patch("aws_clarity_cli.run_local_scan", return_value=incomplete_report), \
                     redirect_stderr(stderr_cfg):
                    rc2 = aws_clarity_cli.main(["scan", "--yes", "--output", out_path])
            self.assertEqual(rc2, 0)
            self.assertIn("Next: open https://dashboard.example.internal/ and import", stderr_cfg.getvalue())

    def test_actionable_error_messages_explain_what_why_and_next_without_leaking_secrets(self):
        # 1. Missing profile
        with patch("local_engine.boto3.Session", side_effect=ProfileNotFound(profile="ghost-profile")):
            with self.assertRaises(RuntimeError) as ctx:
                local_engine.create_local_session(profile="ghost-profile")
        msg = str(ctx.exception)
        self.assertIn("ghost-profile", msg)
        self.assertIn("Why:", msg)
        self.assertIn("Next:", msg)
        self.assertIn("aws configure list-profiles", msg)

        # 2. Missing credentials
        no_cred_session = MagicMock()
        no_cred_sts = MagicMock()
        no_cred_sts.get_caller_identity.side_effect = NoCredentialsError()
        no_cred_session.client.return_value = no_cred_sts
        with self.assertRaises(RuntimeError) as ctx2:
            local_engine.verify_identity(no_cred_session)
        self.assertIn("Why:", str(ctx2.exception))
        self.assertIn("Next:", str(ctx2.exception))
        self.assertIn("aws sso login", str(ctx2.exception))

        # 3. Expired SSO token
        sso_session = MagicMock()
        sso_sts = MagicMock()
        sso_sts.get_caller_identity.side_effect = TokenRetrievalError(provider="sso", error_msg="expired")
        sso_session.client.return_value = sso_sts
        with self.assertRaises(RuntimeError) as ctx3:
            local_engine.verify_identity(sso_session)
        self.assertIn("Why:", str(ctx3.exception))
        self.assertIn("Next:", str(ctx3.exception))
        self.assertIn("aws sso login", str(ctx3.exception))

        # 4. AssumeRole error masks account ID in role ARN and gives actionable guidance
        base_sess = MagicMock()
        sts_client = MagicMock()
        sts_client.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
            "AssumeRole",
        )
        base_sess.client.return_value = sts_client
        with patch("local_engine.boto3.Session", return_value=base_sess):
            with self.assertRaises(AssumeRoleError) as ctx4:
                local_engine.create_local_session(role_arn="arn:aws:iam::987654321098:role/AuditRole")
        self.assertIn("********1098", str(ctx4.exception))
        self.assertNotIn("987654321098", str(ctx4.exception))
        self.assertIn("Why:", str(ctx4.exception))
        self.assertIn("Next:", str(ctx4.exception))


if __name__ == "__main__":
    unittest.main()
