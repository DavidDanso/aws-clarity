"""Phase 1 Unknown-Environment Hardening Regression Tests.

Covers:
  1.2 Identity & credential guards (root block, --allow-root, admin name-heuristic
      warning with zero extra IAM calls, pre-scan confirmation prompt + --yes,
      credential scrubbing, no silent profile fallback).
  1.3 Authoritative API operation allowlist enforced at boto3/botocore client layer
      (blocks mutations & unlisted reads; policy-to-allowlist 1:1 parity).
  1.4 Field-level data minimization & canary secret leak prevention across all
      15 collectors, full scan report, stdout, and stderr.
  1.5 Zero-telemetry socket/network proof, static AST read-only audit, and
      local --role-arn AssumeRole isolation.
  1.6 CloudFormation read-only role template parity with build_policy_document().
"""

import ast
import datetime
import io
import json
import os
import re
import socket
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError, ProfileNotFound

sys.path.insert(0, os.path.dirname(__file__))

import api_guard
import aws_clarity_cli
import local_engine
from exceptions import RootIdentityBlockedError
from scanner import (
    cloudtrail,
    cloudwatch,
    dynamodb_tables,
    ebs,
    ec2,
    elastic_ip,
    iam,
    internet_gateways,
    lambda_functions,
    nat_gateways,
    rds,
    security_group,
    snapshots,
    vpcs,
)
from utils import CachedSession, redact_credential_strings

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestPhase1IdentityAndCredentialGuards(unittest.TestCase):
    def test_root_arn_blocked_by_default_in_scan_and_doctor(self):
        root_ident = {
            "account_id": "123456789012",
            "caller_arn": "arn:aws:iam::123456789012:root",
            "user_id": "123456789012",
        }
        fake_session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {
            "Account": root_ident["account_id"],
            "Arn": root_ident["caller_arn"],
            "UserId": root_ident["user_id"],
        }
        fake_session.client.return_value = sts

        with self.assertRaises(RootIdentityBlockedError) as ctx:
            local_engine.run_doctor(fake_session, allow_root=False)
        self.assertIn("--allow-root", str(ctx.exception))
        self.assertIn("********9012", str(ctx.exception))

        with self.assertRaises(RootIdentityBlockedError):
            local_engine.run_local_scan(fake_session, regions=["us-east-1"], allow_root=False)

        # CLI scan refuses root with exit code 2 before running any collector
        stderr_buf = io.StringIO()
        with patch("aws_clarity_cli.create_local_session", return_value=fake_session), \
             patch("aws_clarity_cli.verify_identity", return_value=root_ident), \
             patch("aws_clarity_cli.run_local_scan") as mock_scan, \
             redirect_stderr(stderr_buf):
            rc = aws_clarity_cli.main(["scan", "--yes", "--output", "-"])
        self.assertEqual(rc, 2)
        mock_scan.assert_not_called()
        self.assertIn("root", stderr_buf.getvalue().lower())
        self.assertNotIn("123456789012", stderr_buf.getvalue())

        # CLI doctor also refuses root unless --allow-root
        stderr_doc = io.StringIO()
        with patch("aws_clarity_cli.create_local_session", return_value=fake_session), \
             redirect_stderr(stderr_doc):
            rc_doc = aws_clarity_cli.main(["doctor"])
        self.assertEqual(rc_doc, 2)
        self.assertIn("--allow-root", stderr_doc.getvalue())

    def test_allow_root_override_permits_explicit_run(self):
        root_ident = {
            "account_id": "123456789012",
            "caller_arn": "arn:aws:iam::123456789012:root",
            "user_id": "123456789012",
        }
        fake_report = {
            "schema_version": "aws-clarity-report/v1",
            "scanner_version": local_engine.CLI_VERSION,
            "execution_mode": "local-cli",
            "status": "COMPLETE",
            "account_id": "123456789012",
            "caller_arn": root_ident["caller_arn"],
            "regions": ["us-east-1"],
            "scan_duration_ms": 100,
            "summary": {"total_resources": 0, "critical_issues": 0, "warnings": 0, "unused": 0, "info_observations": 0},
            "coverage": {"status": "COMPLETE", "services_skipped_optional": ["S3"], "failures": []},
            "resources": {"vpcs": []},
        }
        with patch("aws_clarity_cli.create_local_session", return_value=MagicMock()), \
             patch("aws_clarity_cli.verify_identity", return_value=root_ident), \
             patch("aws_clarity_cli.run_local_scan", return_value=fake_report) as mock_scan, \
             redirect_stdout(io.StringIO()), \
             redirect_stderr(io.StringIO()):
            rc = aws_clarity_cli.main(["scan", "--allow-root", "--yes", "--output", "-"])
        self.assertEqual(rc, 0)
        self.assertTrue(mock_scan.call_args.kwargs["allow_root"])

    def test_admin_name_heuristic_warns_without_blocking_or_extra_iam_calls(self):
        self.assertTrue(local_engine.is_likely_admin_name_heuristic("arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_abc/alice"))
        self.assertTrue(local_engine.is_likely_admin_name_heuristic("arn:aws:iam::123456789012:user/platform-Admin"))
        self.assertFalse(local_engine.is_likely_admin_name_heuristic("arn:aws:sts::123456789012:assumed-role/ReadOnlyRole/admin-session"))
        self.assertFalse(local_engine.is_likely_admin_name_heuristic("arn:aws:iam::123456789012:user/dev-auditor"))

        admin_ident = {
            "account_id": "123456789012",
            "caller_arn": "arn:aws:sts::123456789012:assumed-role/CompanyAdministrator/bob",
            "user_id": "AROA123:bob",
        }
        fake_session = MagicMock()
        fake_report = {
            "schema_version": "aws-clarity-report/v1",
            "scanner_version": local_engine.CLI_VERSION,
            "execution_mode": "local-cli",
            "status": "COMPLETE",
            "account_id": "123456789012",
            "caller_arn": admin_ident["caller_arn"],
            "regions": ["us-east-1"],
            "scan_duration_ms": 100,
            "summary": {"total_resources": 0, "critical_issues": 0, "warnings": 0, "unused": 0, "info_observations": 0},
            "coverage": {"status": "COMPLETE", "services_skipped_optional": ["S3"], "failures": []},
            "resources": {"vpcs": []},
        }
        stderr_buf = io.StringIO()
        with patch("aws_clarity_cli.create_local_session", return_value=fake_session), \
             patch("aws_clarity_cli.verify_identity", return_value=admin_ident), \
             patch("aws_clarity_cli.run_local_scan", return_value=fake_report), \
             redirect_stdout(io.StringIO()), \
             redirect_stderr(stderr_buf):
            rc = aws_clarity_cli.main(["scan", "--yes", "--output", "-"])
        self.assertEqual(rc, 0)
        err = stderr_buf.getvalue()
        self.assertIn("NAME HEURISTIC ONLY", err)
        self.assertIn("aws-clarity policy --zero-cost-only", err)
        # Zero extra IAM calls made on fake_session during identity guard check
        fake_session.client.assert_not_called()

    def test_prescan_confirmation_blocks_without_yes_or_consent_and_masks_account(self):
        ident = {
            "account_id": "123456789012",
            "caller_arn": "arn:aws:sts::123456789012:assumed-role/LocalReadOnly/dev",
            "user_id": "AROA123:dev",
        }
        # 1. Non-interactive without --yes -> aborts with exit 2 before calling run_local_scan
        stderr_buf = io.StringIO()
        with patch("aws_clarity_cli.create_local_session", return_value=MagicMock()), \
             patch("aws_clarity_cli.verify_identity", return_value=ident), \
             patch("aws_clarity_cli.run_local_scan") as mock_scan, \
             patch("sys.stdin.isatty", return_value=False), \
             redirect_stderr(stderr_buf):
            rc = aws_clarity_cli.main(["scan", "--profile", "sandbox", "--output", "-"])
        self.assertEqual(rc, 2)
        mock_scan.assert_not_called()
        out = stderr_buf.getvalue()
        self.assertIn("********9012", out)
        self.assertNotIn("123456789012", out)
        self.assertIn("--yes", out)
        self.assertIn("NOT Collected", out)

        # 2. Interactive user answers 'n', 'no', or empty input '' (default No) -> aborts before run_local_scan
        for decline in ("n", "no", "", "   "):
            with patch("aws_clarity_cli.create_local_session", return_value=MagicMock()), \
                 patch("aws_clarity_cli.verify_identity", return_value=ident), \
                 patch("aws_clarity_cli.run_local_scan") as mock_scan, \
                 patch("sys.stdin.isatty", return_value=True), \
                 patch("builtins.input", return_value=decline), \
                 redirect_stderr(io.StringIO()):
                rc_no = aws_clarity_cli.main(["scan", "--output", "-"])
            self.assertEqual(rc_no, 2, f"Expected decline for input {decline!r}")
            mock_scan.assert_not_called()

        # 3. Interactive user answers 'y' or 'YES' -> proceeds and invokes run_local_scan
        fake_report = {
            "schema_version": "aws-clarity-report/v1",
            "scanner_version": local_engine.CLI_VERSION,
            "execution_mode": "local-cli",
            "status": "COMPLETE",
            "account_id": "123456789012",
            "caller_arn": ident["caller_arn"],
            "regions": ["us-east-1"],
            "scan_duration_ms": 50,
            "summary": {"total_resources": 0, "critical_issues": 0, "warnings": 0, "unused": 0, "info_observations": 0},
            "coverage": {"status": "COMPLETE", "services_skipped_optional": ["S3"], "failures": []},
            "resources": {"vpcs": []},
        }
        for accept in ("y", "YES"):
            with patch("aws_clarity_cli.create_local_session", return_value=MagicMock()), \
                 patch("aws_clarity_cli.verify_identity", return_value=ident), \
                 patch("aws_clarity_cli.run_local_scan", return_value=fake_report) as mock_scan, \
                 patch("sys.stdin.isatty", return_value=True), \
                 patch("builtins.input", return_value=accept), \
                 redirect_stdout(io.StringIO()), \
                 redirect_stderr(io.StringIO()):
                rc_yes = aws_clarity_cli.main(["scan", "--output", "-"])
            self.assertEqual(rc_yes, 0, f"Expected accept for input {accept!r}")
            mock_scan.assert_called_once()

    def test_missing_profile_never_falls_back_and_errors_redact_credentials(self):
        with patch("local_engine.boto3.Session", side_effect=ProfileNotFound(profile="missing-prof")):
            with self.assertRaises(RuntimeError) as ctx:
                local_engine.create_local_session(profile="missing-prof")
            self.assertIn("Refusing to fall back", str(ctx.exception))

        scrubbed = redact_credential_strings(
            "Error AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY SessionToken=FwoGZXIvYXdzEBa"
        )
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", scrubbed)
        self.assertNotIn("wJalrXUtnFEMI", scrubbed)
        self.assertNotIn("FwoGZXIvYXdzEBa", scrubbed)


class TestPhase1ApiAllowlistEnforcement(unittest.TestCase):
    def test_allowlist_matches_iam_policy_1_to_1(self):
        self.assertEqual(
            local_engine.build_policy_document(include_s3=False)["Statement"][0]["Action"],
            api_guard.get_allowed_iam_actions(include_s3=False),
        )
        self.assertEqual(
            local_engine.build_policy_document(include_s3=True)["Statement"][0]["Action"],
            api_guard.get_allowed_iam_actions(include_s3=True),
        )
        self.assertEqual(len(api_guard.get_allowed_iam_actions(include_s3=False)), 28)
        self.assertEqual(len(api_guard.get_allowed_iam_actions(include_s3=True)), 34)

    def test_guarded_client_blocks_mutations_and_unlisted_reads_on_real_botocore_and_mocks(self):
        # 1. Real botocore client (no network needed — guard intercepts before HTTP/endpoint call)
        real_sess = boto3.Session(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            region_name="us-east-1",
        )
        guarded_sess = CachedSession(real_sess, enforce_api_allowlist=True, include_s3=False)

        ec2_client = guarded_sess.client("ec2", region_name="us-east-1")
        for forbidden_call in (
            lambda: ec2_client.terminate_instances(InstanceIds=["i-1234"]),
            lambda: ec2_client.delete_security_group(GroupId="sg-1234"),
            lambda: ec2_client.authorize_security_group_ingress(GroupId="sg-1234"),
            lambda: ec2_client.describe_tags(),  # unlisted read also blocked!
            lambda: ec2_client.get_paginator("describe_tags"),
        ):
            with self.assertRaises(api_guard.DisallowedAWSOperationError):
                forbidden_call()

        iam_client = guarded_sess.client("iam")
        for forbidden_call in (
            lambda: iam_client.put_role_policy(RoleName="r", PolicyName="p", PolicyDocument="{}"),
            lambda: iam_client.delete_access_key(UserName="u", AccessKeyId="AKIA123"),
            lambda: iam_client.create_role(RoleName="r", AssumeRolePolicyDocument="{}"),
        ):
            with self.assertRaises(api_guard.DisallowedAWSOperationError):
                forbidden_call()

        # When include_s3=False, even allowlisted S3 operations are blocked at the client layer!
        s3_client_off = guarded_sess.client("s3")
        with self.assertRaises(api_guard.DisallowedAWSOperationError):
            s3_client_off.list_buckets()

        # When include_s3=True, object listing & object reads are STILL blocked!
        guarded_s3_on = CachedSession(real_sess, enforce_api_allowlist=True, include_s3=True)
        s3_client_on = guarded_s3_on.client("s3")
        for forbidden_s3 in (
            lambda: s3_client_on.list_objects_v2(Bucket="my-bucket"),
            lambda: s3_client_on.get_object(Bucket="my-bucket", Key="secret.txt"),
            lambda: s3_client_on.delete_bucket(Bucket="my-bucket"),
            lambda: s3_client_on.put_bucket_policy(Bucket="my-bucket", Policy="{}"),
        ):
            with self.assertRaises(api_guard.DisallowedAWSOperationError):
                forbidden_s3()

        # Also test botocore's before-call hook directly on the raw underlying client!
        with self.assertRaises(api_guard.DisallowedAWSOperationError):
            ec2_client._raw_client.terminate_instances(InstanceIds=["i-1234"])


class TestPhase1DataMinimizationAndCanarySecrets(unittest.TestCase):
    def test_canary_secrets_never_enter_report_stdout_or_stderr(self):
        canaries = [
            "CANARY_SECRET_LAMBDA_ENV_VALUE",
            "CANARY_SECRET_LAMBDA_ENV_KEY",
            "CANARY_LAMBDA_DESC_SECRET",
            "CANARY_TAG_TOKEN_EC2",
            "CANARY_TAG_TOKEN_EIP",
            "CANARY_TAG_TOKEN_VPC",
            "CANARY_TAG_TOKEN_IGW",
            "CANARY_TAG_TOKEN_NAT",
            "CANARY_TAG_TOKEN_EBS",
            "CANARY_TAG_TOKEN_SNAP",
            "CANARY_SG_DESC_SECRET",
            "CANARY_SG_RULE_DESC_SECRET",
            "CANARY_SNAP_DESC_SECRET",
            "CANARY_IAM_COND_SECRET",
            "CANARY_IAM_RES_SECRET",
            "CANARY_IAM_TRUST_EXT_SECRET",
            "CANARY_IAM_SID_SECRET",
            "CANARY_RDS_ENDPOINT_SECRET.rds.amazonaws.com",
            "CANARY_RDS_MASTER_USER",
            "CANARY_DDB_KMS_KEY_SECRET",
            "CANARY_CW_ALARM_DESC_SECRET",
            "CANARY_CW_ACTION_ARN_SECRET",
            "CANARY_LOGS_KMS_SECRET",
            "CANARY_CT_KMS_SECRET",
            "CANARY_CT_DELIVERY_ERR_SECRET",
        ]

        mock_session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/LocalReadOnly/tester",
            "UserId": "AROA123:tester",
        }

        ec2_c = MagicMock()
        ec2_c.describe_addresses.return_value = {
            "Addresses": [{
                "AllocationId": "eipalloc-1",
                "PublicIp": "198.51.100.10",
                "AssociationId": None,
                "Domain": "vpc",
                "Tags": [{"Key": "Name", "Value": "web-eip"}, {"Key": "SecretToken", "Value": "CANARY_TAG_TOKEN_EIP"}],
            }]
        }

        def ec2_paginator(op):
            p = MagicMock()
            if op == "describe_instances":
                p.paginate.return_value = [{"Reservations": [{"Instances": [{
                    "InstanceId": "i-001",
                    "InstanceType": "t3.micro",
                    "State": {"Name": "running"},
                    "VpcId": "vpc-1",
                    "SubnetId": "subnet-1",
                    "MetadataOptions": {"HttpTokens": "required"},
                    "PrivateIpAddress": "10.0.1.99",
                    "Tags": [{"Key": "Name", "Value": "app-01"}, {"Key": "ApiKey", "Value": "CANARY_TAG_TOKEN_EC2"}],
                }]}]}]
            elif op == "describe_security_groups":
                p.paginate.return_value = [{"SecurityGroups": [{
                    "GroupId": "sg-001",
                    "GroupName": "web-sg",
                    "Description": "Contains CANARY_SG_DESC_SECRET",
                    "VpcId": "vpc-1",
                    "IpPermissions": [{
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "CANARY_SG_RULE_DESC_SECRET"}],
                    }],
                }]}]
            elif op == "describe_vpcs":
                p.paginate.return_value = [{"Vpcs": [{
                    "VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16", "IsDefault": False, "State": "available",
                    "Tags": [{"Key": "Name", "Value": "main-vpc"}, {"Key": "Token", "Value": "CANARY_TAG_TOKEN_VPC"}],
                }]}]
            elif op == "describe_internet_gateways":
                p.paginate.return_value = [{"InternetGateways": [{
                    "InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1", "State": "available"}],
                    "Tags": [{"Key": "Token", "Value": "CANARY_TAG_TOKEN_IGW"}],
                }]}]
            elif op == "describe_nat_gateways":
                p.paginate.return_value = [{"NatGateways": [{
                    "NatGatewayId": "nat-1", "State": "available", "VpcId": "vpc-1", "SubnetId": "subnet-1",
                    "Tags": [{"Key": "Token", "Value": "CANARY_TAG_TOKEN_NAT"}],
                }]}]
            elif op == "describe_volumes":
                p.paginate.return_value = [{"Volumes": [{
                    "VolumeId": "vol-1", "Size": 20, "State": "in-use", "Encrypted": True, "VolumeType": "gp3",
                    "Attachments": [{"InstanceId": "i-001", "State": "attached"}],
                    "Tags": [{"Key": "Token", "Value": "CANARY_TAG_TOKEN_EBS"}],
                }]}]
            elif op == "describe_snapshots":
                p.paginate.return_value = [{"Snapshots": [{
                    "SnapshotId": "snap-1", "VolumeId": "vol-1", "VolumeSize": 20, "Encrypted": True,
                    "Description": "Backup with CANARY_SNAP_DESC_SECRET",
                    "Tags": [{"Key": "Token", "Value": "CANARY_TAG_TOKEN_SNAP"}],
                }]}]
            return p

        ec2_c.get_paginator.side_effect = ec2_paginator

        iam_c = MagicMock()

        def iam_paginator(op):
            p = MagicMock()
            if op == "list_roles":
                p.paginate.return_value = [{"Roles": [{
                    "RoleName": "AppRole",
                    "RoleId": "AROA001",
                    "Arn": "arn:aws:iam::123456789012:role/AppRole",
                    "Path": "/",
                    "AssumeRolePolicyDocument": {
                        "Statement": [{
                            "Sid": "CANARY_IAM_SID_SECRET",
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                            "Action": "sts:AssumeRole",
                            "Condition": {"StringEquals": {"sts:ExternalId": "CANARY_IAM_TRUST_EXT_SECRET"}},
                        }]
                    },
                }]}]
            elif op == "list_role_policies":
                p.paginate.return_value = [{"PolicyNames": ["InlineApp"]}]
            elif op == "list_attached_role_policies":
                p.paginate.return_value = [{"AttachedPolicies": []}]
            elif op == "list_users":
                p.paginate.return_value = [{"Users": []}]
            return p

        iam_c.get_paginator.side_effect = iam_paginator
        iam_c.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [{
                    "Sid": "CANARY_IAM_SID_SECRET",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::bucket/CANARY_IAM_RES_SECRET",
                    "Condition": {"StringEquals": {"aws:RequestTag/Token": "CANARY_IAM_COND_SECRET"}},
                }]
            }
        }

        lam_c = MagicMock()
        lam_c.get_paginator.return_value.paginate.return_value = [{"Functions": [{
            "FunctionName": "billing-fn",
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:billing-fn",
            "Runtime": "python3.12",
            "PackageType": "Zip",
            "LastModified": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "Description": "CANARY_LAMBDA_DESC_SECRET",
            "Environment": {"Variables": {"CANARY_SECRET_LAMBDA_ENV_KEY": "CANARY_SECRET_LAMBDA_ENV_VALUE"}},
        }]}]

        rds_c = MagicMock()
        rds_c.get_paginator.return_value.paginate.return_value = [{"DBInstances": [{
            "DBInstanceIdentifier": "prod-db",
            "DBInstanceClass": "db.t3.medium",
            "Engine": "postgres",
            "PubliclyAccessible": True,
            "StorageEncrypted": True,
            "DeletionProtection": True,
            "BackupRetentionPeriod": 7,
            "Endpoint": {"Address": "CANARY_RDS_ENDPOINT_SECRET.rds.amazonaws.com", "Port": 5432},
            "MasterUsername": "CANARY_RDS_MASTER_USER",
        }]}]

        ddb_c = MagicMock()
        ddb_c.list_tables.return_value = {"TableNames": ["orders"]}
        ddb_c.describe_table.return_value = {"Table": {
            "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/orders",
            "TableStatus": "ACTIVE",
            "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "ItemCount": 10,
            "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": "arn:aws:kms:us-east-1:123456789012:key/CANARY_DDB_KMS_KEY_SECRET"},
        }}

        cw_c = MagicMock()
        cw_c.get_paginator.return_value.paginate.return_value = [{"MetricAlarms": [{
            "AlarmName": "high-cpu",
            "AlarmArn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:high-cpu",
            "AlarmDescription": "CANARY_CW_ALARM_DESC_SECRET",
            "StateValue": "OK",
            "ActionsEnabled": True,
            "AlarmActions": ["arn:aws:sns:us-east-1:123456789012:CANARY_CW_ACTION_ARN_SECRET"],
        }]}]

        logs_c = MagicMock()
        logs_c.get_paginator.return_value.paginate.return_value = [{"logGroups": [{
            "logGroupName": "/aws/lambda/billing-fn",
            "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/billing-fn",
            "retentionInDays": 30,
            "storedBytes": 1024,
            "kmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/CANARY_LOGS_KMS_SECRET",
        }]}]

        ct_c = MagicMock()
        ct_c.describe_trails.return_value = {"trailList": [{
            "Name": "org-trail",
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
            "HomeRegion": "us-east-1",
            "S3BucketName": "audit-logs-bucket",
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/CANARY_CT_KMS_SECRET",
        }]}
        ct_c.get_trail_status.return_value = {
            "IsLogging": True,
            "LatestDeliveryError": "CANARY_CT_DELIVERY_ERR_SECRET",
        }

        clients = {
            "sts": sts,
            "ec2": ec2_c,
            "iam": iam_c,
            "lambda": lam_c,
            "rds": rds_c,
            "dynamodb": ddb_c,
            "cloudwatch": cw_c,
            "logs": logs_c,
            "cloudtrail": ct_c,
        }
        mock_session.client.side_effect = lambda svc, **kw: clients[svc]

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "canary-report.json")
            stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
            with patch("aws_clarity_cli.create_local_session", return_value=mock_session), \
                 redirect_stdout(stdout_buf), \
                 redirect_stderr(stderr_buf):
                rc = aws_clarity_cli.main(["scan", "--regions", "us-east-1", "--yes", "--output", out_path])

            self.assertEqual(rc, 0)
            with open(out_path, encoding="utf-8") as fh:
                report_text = fh.read()
            combined = report_text + "\n" + stdout_buf.getvalue() + "\n" + stderr_buf.getvalue()

            for canary in canaries:
                self.assertNotIn(canary, combined, f"Canary secret leaked into report or CLI output: {canary}")

            # Verify core rules STILL worked accurately after field minimization!
            report = json.loads(report_text)
            sg_issues = [i["rule_id"] for i in report["resources"]["security_groups"][0]["issues"]]
            rds_issues = [i["rule_id"] for i in report["resources"]["rds_instances"][0]["issues"]]
            self.assertIn("SG-002", sg_issues)
            self.assertIn("RDS-001", rds_issues)
            # Lambda kept boolean fact without leaking env vars
            lam_raw = report["resources"]["lambda_functions"][0]["raw"]
            self.assertIs(lam_raw["has_environment_variables"], True)
            self.assertNotIn("Environment", lam_raw)
            # IAM role passed IAM-008 because sts:ExternalId key was preserved while its secret value was dropped!
            self.assertEqual(report["resources"]["iam_roles"][0]["status"], "HEALTHY")
            # Raw inline/trust policy documents were pruned post-evaluation
            self.assertNotIn("inline_policies", report["resources"]["iam_roles"][0]["raw"])
            self.assertNotIn("trust_policy", report["resources"]["iam_roles"][0]["raw"])


class TestPhase1ZeroTelemetryReadOnlyAndCfnTemplate(unittest.TestCase):
    def test_zero_telemetry_no_non_aws_network_calls(self):
        contacted_hosts = []

        def guard_getaddrinfo(host, *args, **kwargs):
            contacted_hosts.append(str(host))
            if not str(host).endswith(".amazonaws.com"):
                raise AssertionError(f"Non-AWS host contacted: {host}")
            raise OSError("Simulated offline network")

        def fail_urlopen(url, *args, **kwargs):
            raise AssertionError(f"Unexpected HTTP call via urllib: {url}")

        fake_session = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/LocalReadOnly/dev",
            "UserId": "AROA123:dev",
        }
        empty_client = MagicMock()
        empty_client.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        empty_client.describe_addresses.return_value = {"Addresses": []}
        empty_client.list_tables.return_value = {"TableNames": []}
        empty_client.describe_trails.return_value = {"trailList": []}
        empty_client.get_paginator.return_value.paginate.return_value = []
        fake_session.client.side_effect = lambda svc, **kw: sts if svc == "sts" else empty_client

        with patch("socket.getaddrinfo", side_effect=guard_getaddrinfo), \
             patch("urllib.request.urlopen", side_effect=fail_urlopen):
            local_engine.run_doctor(fake_session, include_s3_checks=False)
            local_engine.run_local_scan(fake_session, regions=["us-east-1"], include_s3_checks=False)

        for host in contacted_hosts:
            self.assertTrue(host.endswith(".amazonaws.com"), f"Non-AWS host contacted: {host}")

    def test_static_ast_audit_confirms_no_aws_mutations_in_local_scanner_paths(self):
        forbidden_prefixes = (
            "create_", "delete_", "put_", "update_", "modify_", "terminate_",
            "stop_", "start_", "attach_", "detach_", "authorize_", "revoke_",
            "associate_", "disassociate_", "release_", "reboot_",
        )
        scan_files = [
            os.path.join(REPO_ROOT, "backend", "local_engine.py"),
            os.path.join(REPO_ROOT, "backend", "aws_clarity_cli.py"),
            os.path.join(REPO_ROOT, "backend", "api_guard.py"),
        ]
        scanner_dir = os.path.join(REPO_ROOT, "backend", "scanner")
        for fname in sorted(os.listdir(scanner_dir)):
            if fname.endswith(".py"):
                scan_files.append(os.path.join(scanner_dir, fname))

        for path in scan_files:
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    attr = node.func.attr
                    # Exclude local_engine.create_local_session (helper function, not an AWS client call)
                    if attr == "create_local_session":
                        continue
                    self.assertFalse(
                        attr.startswith(forbidden_prefixes),
                        f"Forbidden mutation-like call '{attr}' found in {os.path.relpath(path, REPO_ROOT)}:{node.lineno}",
                    )

    def test_role_arn_assumption_only_calls_sts_assume_role_and_never_modifies_iam(self):
        base_session = MagicMock()
        sts_client = MagicMock()
        sts_client.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIAEXAMPLEKEY123456",
                "SecretAccessKey": "dummy-secret-for-unit-test-only",
                "SessionToken": "dummy-session-token-for-unit-test-only",
            }
        }
        base_session.client.return_value = sts_client

        with patch("local_engine.boto3.Session", side_effect=[base_session, MagicMock()]) as mock_sess_cls:
            local_engine.create_local_session(
                profile="base-prof",
                role_arn="arn:aws:iam::123456789012:role/MyReadOnlyRole",
                external_id="my-ext-id-123",
            )

        base_session.client.assert_called_once()
        self.assertEqual(base_session.client.call_args.args[0], "sts")
        sts_client.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/MyReadOnlyRole",
            RoleSessionName="AWSClarityLocalScan",
            DurationSeconds=3600,
            ExternalId="my-ext-id-123",
        )
        self.assertEqual(mock_sess_cls.call_count, 2)

    def test_cloudformation_readonly_role_template_matches_policy_exactly(self):
        cfn_path = os.path.join(REPO_ROOT, "infra", "aws-clarity-readonly-role.yaml")
        self.assertTrue(os.path.isfile(cfn_path), "CloudFormation template infra/aws-clarity-readonly-role.yaml must exist")
        with open(cfn_path, encoding="utf-8") as fh:
            text = fh.read()

        # Verify required parameters exist
        self.assertIn("TrustedPrincipalArn:", text)
        self.assertIn("ExternalId:", text)
        self.assertIn("IncludeS3Checks:", text)
        self.assertIn("sts:ExternalId", text)

        # Extract default actions block and optional S3 actions block from YAML cleanly without external deps
        default_block = text.split("Sid: AWSClarityLocalZeroRequestCostReadOnly")[1].split('Resource: "*"')[0]
        s3_block = text.split("Sid: AWSClarityLocalOptionalS3Metadata")[1].split('Resource: "*"')[0]

        cfn_default_actions = re.findall(r"^\s*-\s+([a-z0-9]+:[A-Za-z0-9]+)\s*$", default_block, re.MULTILINE)
        cfn_s3_actions = re.findall(r"^\s*-\s+([a-z0-9]+:[A-Za-z0-9]+)\s*$", s3_block, re.MULTILINE)

        expected_default = local_engine.build_policy_document(include_s3=False)["Statement"][0]["Action"]
        expected_full = local_engine.build_policy_document(include_s3=True)["Statement"][0]["Action"]

        self.assertEqual(cfn_default_actions, expected_default)
        self.assertEqual(set(cfn_default_actions) | set(cfn_s3_actions), set(expected_full))
        self.assertEqual(len(cfn_default_actions), 28)
        self.assertEqual(len(cfn_s3_actions), 6)


if __name__ == "__main__":
    unittest.main()
