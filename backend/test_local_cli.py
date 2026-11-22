import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError, TokenRetrievalError

sys.path.insert(0, os.path.dirname(__file__))

import aws_clarity_cli
import local_engine


class TestLocalFirstScannerAndCLI(unittest.TestCase):
    def test_policy_documents_match_zero_cost_and_full_scopes(self):
        default_policy = local_engine.build_policy_document(include_s3=False)
        full_policy = local_engine.build_policy_document(include_s3=True)

        default_actions = default_policy["Statement"][0]["Action"]
        full_actions = full_policy["Statement"][0]["Action"]

        self.assertEqual(len(default_actions), 28)
        self.assertEqual(len(full_actions), 34)
        self.assertFalse(any(a.startswith("s3:") for a in default_actions))
        self.assertNotIn("s3:ListBucket", full_actions)
        self.assertNotIn("s3:GetObject", full_actions)
        self.assertNotIn("s3:GetBucketVersioning", full_actions)

    def test_create_local_session_uses_profile_and_supports_sso_expiry_guidance(self):
        with patch("local_engine.boto3.Session") as mock_session_cls:
            local_engine.create_local_session(profile="dev-sso")
            mock_session_cls.assert_called_once_with(profile_name="dev-sso", region_name="us-east-1")

        expired_session = MagicMock()
        expired_sts = MagicMock()
        expired_sts.get_caller_identity.side_effect = TokenRetrievalError(
            provider="sso", error_msg="Token has expired"
        )
        expired_session.client.return_value = expired_sts
        with self.assertRaises(RuntimeError) as ctx:
            local_engine.verify_identity(expired_session)
        self.assertIn("aws sso login", str(ctx.exception))

    def test_doctor_reports_passed_missing_and_skipped_optional_s3(self):
        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_ReadOnly/alice",
            "UserId": "AROA123:alice",
        }
        ec2_client = MagicMock()
        ec2_client.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        rds_client = MagicMock()
        rds_client.describe_db_instances.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
            "DescribeDBInstances",
        )
        ok_client = MagicMock()

        def client_factory(svc, **kw):
            if svc == "sts":
                return sts
            if svc == "ec2":
                return ec2_client
            if svc == "rds":
                return rds_client
            return ok_client

        session.client.side_effect = client_factory
        res = local_engine.run_doctor(session, include_s3_checks=False)

        self.assertEqual(res["account_id"], "123456789012")
        self.assertEqual(res["permission_checks"]["S3"]["status"], "SKIPPED_OPTIONAL")
        self.assertEqual(res["permission_checks"]["RDS"]["status"], "MISSING")
        self.assertEqual(res["permission_checks"]["EC2"]["status"], "PASSED")
        self.assertEqual(res["missing_services"], ["RDS"])
        self.assertEqual(res["status"], "INCOMPLETE")

    def test_local_scan_skips_s3_by_default_and_requires_explicit_consent(self):
        session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/LocalDevReadOnly/dev",
            "UserId": "AROA123:dev",
        }
        ec2_client = MagicMock()
        ec2_client.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        session.client.side_effect = lambda svc, **kw: sts if svc == "sts" else ec2_client

        # Enabling S3 without explicit confirmation must raise ValueError
        with self.assertRaises(ValueError):
            local_engine.run_local_scan(session, include_s3_checks=True, confirm_s3_request_costs=False)

        # Default scan skips S3 cleanly as SKIPPED_OPTIONAL and never invokes s3.scan
        regional_patches = [
            ("ec2", "scan"), ("elastic_ip", "scan"), ("security_group", "scan"),
            ("vpcs", "scan"), ("internet_gateways", "scan"), ("nat_gateways", "scan"),
            ("lambda_functions", "scan"), ("rds", "scan"), ("dynamodb_tables", "scan"),
            ("ebs", "scan"), ("snapshots", "scan"),
            ("cloudwatch", "scan_alarms"), ("cloudwatch", "scan_log_groups"),
            ("cloudtrail", "scan"),
        ]
        with ExitStack() as stack:
            import lambda_handler
            for mod_name, fn_name in regional_patches:
                stack.enter_context(patch.object(getattr(lambda_handler, mod_name), fn_name, return_value=[]))
            stack.enter_context(patch.object(local_engine.iam, "scan_roles", return_value=[]))
            stack.enter_context(patch.object(local_engine.iam, "scan_users", return_value=[]))
            mock_s3_scan = stack.enter_context(patch.object(local_engine.s3, "scan", return_value=[]))

            report = local_engine.run_local_scan(session, regions=["us-east-1"], include_s3_checks=False)

        mock_s3_scan.assert_not_called()
        self.assertEqual(report["schema_version"], "aws-clarity-report/v1")
        self.assertEqual(report["execution_mode"], "local-cli")
        self.assertEqual(report["coverage"]["status"], "COMPLETE")
        self.assertEqual(report["coverage"]["services_skipped_optional"], ["S3"])
        s3_row = next(s for s in report["coverage"]["service_summary"] if s["service"] == "S3")
        self.assertEqual(s3_row["status"], "SKIPPED_OPTIONAL")
        self.assertNotIn("NOT_ASSESSED", json.dumps(report, default=str))

    def test_cli_scan_writes_0600_report_with_zero_credentials(self):
        fake_session = MagicMock()
        fake_report = {
            "schema_version": "aws-clarity-report/v1",
            "scanner_version": local_engine.CLI_VERSION,
            "execution_mode": "local-cli",
            "status": "COMPLETE",
            "account_id": "123456789012",
            "caller_arn": "arn:aws:sts::123456789012:assumed-role/ReadOnly/alice",
            "regions": ["us-east-1"],
            "scan_duration_ms": 420,
            "summary": {
                "total_resources": 0,
                "critical_issues": 0,
                "warnings": 0,
                "unused": 0,
                "info_observations": 0,
            },
            "coverage": {
                "status": "COMPLETE",
                "services_skipped_optional": ["S3"],
                "failures": [],
            },
            "resources": {"vpcs": []},
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.json")
            stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
            with patch("aws_clarity_cli.create_local_session", return_value=fake_session), \
                 patch("aws_clarity_cli.verify_identity", return_value={"account_id": "123456789012", "caller_arn": fake_report["caller_arn"]}), \
                 patch("aws_clarity_cli.run_local_scan", return_value=fake_report), \
                 redirect_stdout(stdout_buf), \
                 redirect_stderr(stderr_buf):
                rc = aws_clarity_cli.main(["scan", "--profile", "dev", "--output", out_path])

            self.assertEqual(rc, 0)
            self.assertIn("123456789012", stderr_buf.getvalue())
            # Ensure output file has owner-only 0600 permissions and contains zero credentials
            file_mode = stat.S_IMODE(os.stat(out_path).st_mode)
            self.assertEqual(file_mode, 0o600)
            with open(out_path, encoding="utf-8") as fh:
                content = fh.read()
            for forbidden in ("SecretAccessKey", "SessionToken", "aws_secret_access_key"):
                self.assertNotIn(forbidden, content)
                self.assertNotIn(forbidden, stderr_buf.getvalue())
                self.assertNotIn(forbidden, stdout_buf.getvalue())

    def test_cli_policy_and_version_commands(self):
        out_default, out_full = io.StringIO(), io.StringIO()
        with redirect_stdout(out_default):
            self.assertEqual(aws_clarity_cli.main(["policy", "--zero-cost-only"]), 0)
        with redirect_stdout(out_full):
            self.assertEqual(aws_clarity_cli.main(["policy"]), 0)
        self.assertEqual(len(json.loads(out_default.getvalue())["Statement"][0]["Action"]), 28)
        self.assertEqual(len(json.loads(out_full.getvalue())["Statement"][0]["Action"]), 34)


if __name__ == "__main__":
    unittest.main()
