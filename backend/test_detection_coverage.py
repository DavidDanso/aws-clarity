import datetime
import json
import os
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))

import lambda_handler
from exceptions import InvalidRoleARNError, ScannerError
from scanner import cloudtrail, cloudwatch, ec2, iam, s3
from scanner.misconfig import (
    CHECKS_BY_RESOURCE,
    RULE_METADATA,
    SERVICE_COVERAGE_MATRIX,
    evaluate,
    get_rules_catalog,
)
from utils import (
    generate_scan_token,
    sanitize_metadata_text,
    validate_external_id,
    validate_role_arn,
    verify_scan_token,
)


class TestScopeAndMatrixIntegrity(unittest.TestCase):
    def test_exactly_ten_supported_services(self):
        expected = [
            "EC2", "VPC", "S3", "IAM", "Lambda",
            "RDS", "DynamoDB", "EBS", "CloudWatch", "CloudTrail",
        ]
        self.assertEqual([s["service"] for s in SERVICE_COVERAGE_MATRIX], expected)
        self.assertEqual(set(lambda_handler.CORE_PERMISSIONS.keys()), set(expected))

    def test_matrix_scanners_rules_are_completely_aligned(self):
        matrix_keys = {
            rt["key"]
            for svc in SERVICE_COVERAGE_MATRIX
            for rt in svc["resource_types"]
        }
        matrix_rules = {rid for svc in SERVICE_COVERAGE_MATRIX for rid in svc["checks"]}
        all_check_ids = {rid for ids in CHECKS_BY_RESOURCE.values() for rid in ids}
        catalog_ids = {c["id"] for c in get_rules_catalog()}

        self.assertEqual(matrix_keys, set(lambda_handler.SCANNER_METADATA.keys()))
        self.assertEqual(matrix_keys, set(CHECKS_BY_RESOURCE.keys()))
        self.assertEqual(matrix_rules, all_check_ids)
        self.assertEqual(catalog_ids, all_check_ids)
        self.assertEqual(set(RULE_METADATA.keys()), all_check_ids)


class TestSecurityAndTenantIsolation(unittest.TestCase):
    def test_role_arn_and_external_id_validation(self):
        self.assertEqual(
            validate_role_arn("arn:aws:iam::123456789012:role/service-role/ClarityRole"),
            "arn:aws:iam::123456789012:role/service-role/ClarityRole",
        )
        with self.assertRaises(InvalidRoleARNError):
            validate_role_arn("arn:aws:iam::123456789012:user/NotARole")

        self.assertEqual(validate_external_id("clarity-tenant-9a8b"), "clarity-tenant-9a8b")
        with self.assertRaises(InvalidRoleARNError):
            validate_external_id("bad spaces")

    def test_scan_token_tenant_isolation(self):
        token, token_hash = generate_scan_token()
        self.assertTrue(verify_scan_token(token, token_hash))
        self.assertFalse(verify_scan_token("wrong-token", token_hash))
        self.assertFalse(verify_scan_token(None, token_hash))

        fake_table = MagicMock()
        fake_table.get_item.return_value = {
            "Item": {
                "scan_id": "scan-123",
                "token_hash": token_hash,
                "status": "COMPLETE",
                "result_gz": lambda_handler._encode_result({"account_id": "123456789012", "resources": {}}),
            }
        }
        with patch("lambda_handler._get_table", return_value=fake_table):
            # Missing token -> 403
            resp_missing = lambda_handler.handle_status({
                "pathParameters": {"scan_id": "scan-123"},
                "headers": {},
            })
            self.assertEqual(resp_missing["statusCode"], 403)

            # Wrong token -> 403
            resp_wrong = lambda_handler.handle_status({
                "pathParameters": {"scan_id": "scan-123"},
                "headers": {"X-Scan-Token": "forged-token"},
            })
            self.assertEqual(resp_wrong["statusCode"], 403)

            # Valid token (case-insensitive header) -> 200
            resp_ok = lambda_handler.handle_status({
                "pathParameters": {"scan_id": "scan-123"},
                "headers": {"x-scan-token": token},
            })
            self.assertEqual(resp_ok["statusCode"], 200)
            body = json.loads(resp_ok["body"])
            self.assertEqual(body["account_id"], "123456789012")

    def test_trigger_never_persists_role_arn_or_external_id_to_dynamodb(self):
        fake_table = MagicMock()
        fake_lambda = MagicMock()
        ctx = MagicMock(invoked_function_arn="arn:aws:lambda:us-east-1:111122223333:function:clarity")
        with patch("lambda_handler._get_table", return_value=fake_table), \
             patch("lambda_handler._get_lambda_client", return_value=fake_lambda):
            resp = lambda_handler.handle_trigger({
                "body": json.dumps({
                    "role_arn": "arn:aws:iam::123456789012:role/AWSClarityReadOnly",
                    "external_id": "unique-secret-ext-id",
                })
            }, ctx)
        self.assertEqual(resp["statusCode"], 202)
        payload = json.loads(resp["body"])
        self.assertIn("scan_id", payload)
        self.assertIn("scan_token", payload)

        stored_item = fake_table.put_item.call_args.kwargs["Item"]
        self.assertNotIn("role_arn", stored_item)
        self.assertNotIn("external_id", stored_item)
        self.assertIn("token_hash", stored_item)
        self.assertNotEqual(stored_item["token_hash"], payload["scan_token"])

    def test_metadata_sanitization(self):
        self.assertEqual(sanitize_metadata_text("prod-db\x00\x07\x1b"), "prod-db")


class TestCollectorsAndPagination(unittest.TestCase):
    def test_ec2_multi_page_pagination(self):
        session = MagicMock()
        client = session.client.return_value
        client.get_paginator.return_value.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"}, "MetadataOptions": {"HttpTokens": "required"}}]}]},
            {"Reservations": [{"Instances": [{"InstanceId": "i-2", "State": {"Name": "stopped"}, "MetadataOptions": {"HttpTokens": "optional"}}]}]},
        ]
        items = ec2.scan(session, "us-east-1")
        self.assertEqual([i["id"] for i in items], ["i-1", "i-2"])
        self.assertEqual(items[0]["service"], "EC2")

    def test_cloudwatch_alarms_and_log_groups_pagination(self):
        session = MagicMock()
        cw = MagicMock()
        logs = MagicMock()
        session.client.side_effect = lambda svc, **kw: cw if svc == "cloudwatch" else logs

        cw.get_paginator.return_value.paginate.return_value = [
            {"MetricAlarms": [{"AlarmName": "cpu-1", "AlarmArn": "arn:a1", "StateValue": "OK", "ActionsEnabled": True}]},
            {"MetricAlarms": [{"AlarmName": "cpu-2", "AlarmArn": "arn:a2", "StateValue": "INSUFFICIENT_DATA", "ActionsEnabled": False}]},
        ]
        logs.get_paginator.return_value.paginate.return_value = [
            {"logGroups": [{"logGroupName": "/aws/lambda/fn1", "arn": "arn:lg1", "retentionInDays": 14, "storedBytes": 1024}]},
            {"logGroups": [{"logGroupName": "/aws/lambda/fn2", "arn": "arn:lg2", "storedBytes": 2048000}]},
        ]

        alarms = cloudwatch.scan_alarms(session, "us-east-1")
        lgs = cloudwatch.scan_log_groups(session, "us-east-1")
        self.assertEqual(len(alarms), 2)
        self.assertEqual(len(lgs), 2)
        self.assertEqual(lgs[1]["raw"]["retention_in_days"], None)

    def test_cloudtrail_home_region_deduplication_and_status(self):
        session = MagicMock()
        ct = session.client.return_value
        ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "org-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
                    "HomeRegion": "us-east-1",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                },
                {
                    "Name": "shadow-trail",
                    "TrailARN": "arn:aws:cloudtrail:eu-west-1:123456789012:trail/shadow-trail",
                    "HomeRegion": "eu-west-1",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                },
            ]
        }
        ct.get_trail_status.return_value = {"IsLogging": True}

        trails = cloudtrail.scan(session, "us-east-1")
        self.assertEqual(len(trails), 1)
        self.assertEqual(trails[0]["name"], "org-trail")
        ct.describe_trails.assert_called_once_with(includeShadowTrails=False)

    def test_iam_users_and_roles_pagination(self):
        session = MagicMock()
        client = session.client.return_value

        def mock_paginator(op):
            p = MagicMock()
            if op == "list_users":
                p.paginate.return_value = [
                    {"Users": [{"UserName": "alice", "UserId": "AIDA1", "Arn": "arn:aws:iam::111122223333:user/alice", "PasswordLastUsed": datetime.datetime.now(datetime.timezone.utc)}]}
                ]
            elif op == "list_mfa_devices":
                p.paginate.return_value = [{"MFADevices": []}]
            elif op == "list_access_keys":
                old_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=120)
                p.paginate.return_value = [{"AccessKeyMetadata": [{"AccessKeyId": "AKIAOLD", "Status": "Active", "CreateDate": old_date}]}]
            elif op == "list_attached_user_policies":
                p.paginate.return_value = [{"AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}]
            elif op == "list_user_policies":
                p.paginate.return_value = [{"PolicyNames": []}]
            return p

        client.get_paginator.side_effect = mock_paginator
        users = iam.scan_users(session)
        self.assertEqual(len(users), 1)
        evaluated = evaluate(None, {"iam_users": users})["iam_users"][0]
        self.assertEqual(evaluated["status"], "CRITICAL")
        self.assertEqual({i["rule_id"] for i in evaluated["issues"]}, {"IAM-009", "IAM-010", "IAM-011"})
        for issue in evaluated["issues"]:
            self.assertTrue(issue.get("verify"), "Every finding must include verification guidance")

    def test_s3_global_pagination(self):
        session = MagicMock()
        client = session.client.return_value
        client.list_buckets.side_effect = [
            {"Buckets": [{"Name": "b1"}], "ContinuationToken": "tok-2"},
            {"Buckets": [{"Name": "b2"}]},
        ]
        client.get_bucket_location.side_effect = [{"LocationConstraint": None}, {"LocationConstraint": "eu-west-1"}]
        client.list_objects_v2.return_value = {"KeyCount": 1}
        client.get_bucket_versioning.return_value = {"Status": "Enabled"}

        buckets = s3.scan(session, selected_regions=None)
        self.assertEqual({(b["id"], b["region"]) for b in buckets}, {("b1", "us-east-1"), ("b2", "eu-west-1")})


class TestContextAwareAccuracy(unittest.TestCase):
    def test_empty_default_vpc_is_healthy_and_exposed_default_vpc_is_warning(self):
        # Empty default VPC -> HEALTHY (no false positive!)
        empty_res = evaluate(None, {
            "vpcs": [{"id": "vpc-default", "name": "default", "type": "vpc", "service": "VPC", "region": "us-east-1", "raw": {"is_default": True, "cidr_block": "172.31.0.0/16"}}],
            "ec2_instances": [],
            "rds_instances": [],
        })
        self.assertEqual(empty_res["vpcs"][0]["status"], "HEALTHY")
        self.assertEqual(empty_res["vpcs"][0]["issues"], [])

        # Default VPC hosting a public EC2 instance -> WARNING (VPC-001)
        exposed_res = evaluate(None, {
            "vpcs": [{"id": "vpc-default", "name": "default", "type": "vpc", "service": "VPC", "region": "us-east-1", "raw": {"is_default": True, "cidr_block": "172.31.0.0/16"}}],
            "ec2_instances": [{"id": "i-pub", "name": "web", "type": "ec2_instance", "service": "EC2", "region": "us-east-1", "raw": {"state": "running", "http_tokens": "required", "vpc_id": "vpc-default", "public_ip": "1.2.3.4"}}],
            "rds_instances": [],
        })
        self.assertEqual(exposed_res["vpcs"][0]["status"], "WARNING")
        self.assertEqual(exposed_res["vpcs"][0]["issues"][0]["rule_id"], "VPC-001")

    def test_iam_context_aware_read_only_vs_write_and_conditions(self):
        resources = {
            "iam_roles": [
                {
                    # Read-only role with Describe*/List*/Get* on Resource: * -> HEALTHY (no false positive!)
                    "id": "AROA-RO",
                    "name": "AWSClarityReadOnly",
                    "type": "iam_role",
                    "service": "IAM",
                    "region": "global",
                    "raw": {
                        "role_name": "AWSClarityReadOnly",
                        "arn": "arn:aws:iam::111122223333:role/AWSClarityReadOnly",
                        "is_service_linked": False,
                        "inline_policies": {
                            "ReadOnly": {
                                "Statement": [{
                                    "Effect": "Allow",
                                    "Action": ["ec2:DescribeInstances", "s3:ListAllMyBuckets", "rds:DescribeDBInstances"],
                                    "Resource": "*",
                                }]
                            }
                        },
                        "attached_managed_policies": [],
                        "trust_policy": {
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                                "Action": "sts:AssumeRole",
                                "Condition": {"StringEquals": {"sts:ExternalId": "unique-id-123"}},
                            }]
                        },
                    },
                },
                {
                    # Write actions on Resource: * without conditions -> WARNING (IAM-002)
                    "id": "AROA-WR",
                    "name": "BroadWriter",
                    "type": "iam_role",
                    "service": "IAM",
                    "region": "global",
                    "raw": {
                        "role_name": "BroadWriter",
                        "arn": "arn:aws:iam::111122223333:role/BroadWriter",
                        "is_service_linked": False,
                        "inline_policies": {
                            "WriteAll": {
                                "Statement": [{
                                    "Effect": "Allow",
                                    "Action": ["ec2:TerminateInstances", "s3:DeleteObject"],
                                    "Resource": "*",
                                }]
                            }
                        },
                        "attached_managed_policies": [],
                        "trust_policy": {"Statement": []},
                    },
                },
                {
                    # AWS service-linked role -> HEALTHY (not falsely flagged)
                    "id": "AROA-SLR",
                    "name": "AWSServiceRoleForSupport",
                    "type": "iam_role",
                    "service": "IAM",
                    "region": "global",
                    "raw": {
                        "role_name": "AWSServiceRoleForSupport",
                        "arn": "arn:aws:iam::111122223333:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
                        "is_service_linked": True,
                        "inline_policies": {},
                        "attached_managed_policies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],
                        "trust_policy": {"Statement": []},
                    },
                },
            ]
        }
        roles = evaluate(None, resources, account_id="111122223333")["iam_roles"]
        self.assertEqual(roles[0]["status"], "HEALTHY")
        self.assertEqual(roles[1]["status"], "WARNING")
        self.assertEqual(roles[1]["issues"][0]["rule_id"], "IAM-002")
        self.assertEqual(roles[2]["status"], "HEALTHY")

    def test_cloudwatch_and_cloudtrail_rules(self):
        resources = {
            "cloudwatch_alarms": [
                {"id": "a1", "name": "a1", "type": "cloudwatch_alarm", "service": "CloudWatch", "region": "us-east-1", "raw": {"actions_enabled": False, "state_value": "INSUFFICIENT_DATA"}}
            ],
            "cloudwatch_log_groups": [
                {"id": "/aws/app", "name": "/aws/app", "type": "cloudwatch_log_group", "service": "CloudWatch", "region": "us-east-1", "raw": {"retention_in_days": None, "stored_bytes": 5_000_000}},
                {"id": "/aws/bounded", "name": "/aws/bounded", "type": "cloudwatch_log_group", "service": "CloudWatch", "region": "us-east-1", "raw": {"retention_in_days": 30, "stored_bytes": 5_000_000}},
            ],
            "cloudtrail_trails": [
                {"id": "arn:t1", "name": "main-trail", "type": "cloudtrail_trail", "service": "CloudTrail", "region": "us-east-1", "raw": {"is_logging": False, "is_multi_region_trail": False, "log_file_validation_enabled": False, "home_region": "us-east-1"}}
            ],
        }
        res = evaluate(None, resources)
        self.assertEqual({i["rule_id"] for i in res["cloudwatch_alarms"][0]["issues"]}, {"CW-001", "CW-002"})
        self.assertEqual(res["cloudwatch_log_groups"][0]["issues"][0]["rule_id"], "CW-003")
        self.assertEqual(res["cloudwatch_log_groups"][1]["status"], "HEALTHY")
        self.assertEqual(res["cloudtrail_trails"][0]["status"], "CRITICAL")
        self.assertEqual({i["rule_id"] for i in res["cloudtrail_trails"][0]["issues"]}, {"CT-001", "CT-002", "CT-003"})

    def test_manual_fix_then_rescan_clears_finding(self):
        # Scan 1: SSH open to 0.0.0.0/0 -> CRITICAL (SG-002)
        sg_before = evaluate(None, {
            "security_groups": [{
                "id": "sg-1", "name": "web", "type": "security_group", "service": "EC2", "region": "us-east-1",
                "raw": {"ip_permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            }]
        })["security_groups"][0]
        self.assertEqual(sg_before["status"], "CRITICAL")
        self.assertEqual(sg_before["issues"][0]["rule_id"], "SG-002")

        # Scan 2: User restricted SSH to office CIDR -> HEALTHY, 0 issues
        sg_after = evaluate(None, {
            "security_groups": [{
                "id": "sg-1", "name": "web", "type": "security_group", "service": "EC2", "region": "us-east-1",
                "raw": {"ip_permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.10/32"}]}]},
            }]
        })["security_groups"][0]
        self.assertEqual(sg_after["status"], "HEALTHY")
        self.assertEqual(sg_after["issues"], [])


class TestAllRegionsAndIncompleteCoverage(unittest.TestCase):
    def test_all_enabled_regions_and_incomplete_permission_disclosure(self):
        session = MagicMock()
        sts_mock = MagicMock()
        sts_mock.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/ReadOnly/AWSClarityScan"}
        ec2_regions_mock = MagicMock()
        ec2_regions_mock.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]}

        session.client.side_effect = lambda svc, **kw: sts_mock if svc == "sts" else ec2_regions_mock

        regional_patches = [
            ("ec2", "scan"), ("elastic_ip", "scan"), ("security_group", "scan"),
            ("vpcs", "scan"), ("internet_gateways", "scan"), ("nat_gateways", "scan"),
            ("lambda_functions", "scan"), ("rds", "scan"), ("dynamodb_tables", "scan"),
            ("ebs", "scan"), ("snapshots", "scan"),
            ("cloudwatch", "scan_alarms"), ("cloudwatch", "scan_log_groups"),
            ("cloudtrail", "scan"),
        ]

        discovered_ec2 = {
            "id": "i-1", "name": "web", "type": "ec2_instance", "service": "EC2", "region": "us-east-1",
            "raw": {"state": "running", "http_tokens": "required"},
        }
        denied = ScannerError("AccessDenied in eu-west-1", [])

        with ExitStack() as stack:
            stack.enter_context(patch("lambda_handler.assume_role", return_value=session))
            stack.enter_context(patch("lambda_handler.validate_permissions", return_value={}))
            for mod_name, fn_name in regional_patches:
                mod = getattr(lambda_handler, mod_name)
                m = stack.enter_context(patch.object(mod, fn_name, return_value=[]))
                if mod_name == "ec2":
                    m.side_effect = lambda sess, reg: [discovered_ec2] if reg == "us-east-1" else (_ for _ in ()).throw(denied)
            stack.enter_context(patch.object(lambda_handler.iam, "scan_roles", return_value=[]))
            stack.enter_context(patch.object(lambda_handler.iam, "scan_users", return_value=[]))
            stack.enter_context(patch.object(lambda_handler.s3, "scan", return_value=[]))

            result = lambda_handler.run_scan("arn:aws:iam::123456789012:role/ReadOnly", regions="all")

        self.assertEqual(result["regions"], ["eu-west-1", "us-east-1"])
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["coverage"]["status"], "INCOMPLETE")
        self.assertTrue(any(f["service"] == "EC2" and f["region"] == "eu-west-1" for f in result["coverage"]["failures"]))
        self.assertEqual(result["resources"]["ec2_instances"][0]["status"], "HEALTHY")
        # Account advisory raised because CloudTrail succeeded with 0 trails
        self.assertEqual(result["account_advisories"][0]["rule_id"], "CT-000")
        # Ensure NOT_ASSESSED never appears anywhere in the serialized payload
        self.assertNotIn("NOT_ASSESSED", json.dumps(result, default=str))


if __name__ == "__main__":
    unittest.main()
