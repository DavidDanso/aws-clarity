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
from scanner.misconfig import CHECKS_BY_RESOURCE, RULE_METADATA, evaluate, get_rules_catalog
from utils import validate_external_id, validate_role_arn


class TestValidationAndCompression(unittest.TestCase):
    def test_validate_role_arn_supports_paths_and_rejects_invalid(self):
        self.assertEqual(
            validate_role_arn("arn:aws:iam::123456789012:role/AWSClarityReadOnly"),
            "arn:aws:iam::123456789012:role/AWSClarityReadOnly",
        )
        self.assertEqual(
            validate_role_arn("arn:aws:iam::123456789012:role/service-role/team/ScannerRole"),
            "arn:aws:iam::123456789012:role/service-role/team/ScannerRole",
        )
        with self.assertRaises(InvalidRoleARNError):
            validate_role_arn("arn:aws:iam::12345:role/BadAccount")
        with self.assertRaises(InvalidRoleARNError):
            validate_role_arn("arn:aws:iam::123456789012:user/NotARole")

    def test_validate_external_id(self):
        self.assertEqual(validate_external_id(None), "aws-clarity-scan")
        self.assertEqual(validate_external_id(""), "aws-clarity-scan")
        self.assertEqual(validate_external_id("clarity-tenant-99a8"), "clarity-tenant-99a8")
        with self.assertRaises(InvalidRoleARNError):
            validate_external_id("x")
        with self.assertRaises(InvalidRoleARNError):
            validate_external_id("bad spaces here")

    def test_dynamodb_result_compression_roundtrip(self):
        sample = {
            "status": "success",
            "account_id": "123456789012",
            "resources": {"ec2_instances": [{"id": "i-1", "name": "web", "status": "HEALTHY", "issues": []}]},
        }
        encoded, is_gz = lambda_handler._encode_result(sample)
        self.assertTrue(is_gz)
        decoded = lambda_handler._decode_result({"result_gz": encoded})
        self.assertEqual(decoded["account_id"], "123456789012")
        self.assertEqual(decoded["resources"]["ec2_instances"][0]["id"], "i-1")

        # Legacy uncompressed items still decode cleanly
        legacy = lambda_handler._decode_result({"result": json.dumps(sample)})
        self.assertEqual(legacy["account_id"], "123456789012")


class TestRulesCatalogConsistency(unittest.TestCase):
    def test_every_registered_rule_has_catalog_metadata(self):
        catalog_ids = {c["id"] for c in get_rules_catalog()}
        all_check_ids = {rid for ids in CHECKS_BY_RESOURCE.values() for rid in ids}
        self.assertEqual(catalog_ids, all_check_ids)
        self.assertEqual(set(RULE_METADATA.keys()), all_check_ids)

    def test_scanner_metadata_matches_checks_by_resource(self):
        self.assertEqual(set(lambda_handler.SCANNER_METADATA.keys()), set(CHECKS_BY_RESOURCE.keys()))


class TestDetectionCoverage(unittest.TestCase):
    def test_security_group_wide_range_triggers_ssh_rdp_and_db_rules(self):
        """A wide TCP range (0-65535) must flag SG-002, SG-003, and SG-004 without short-circuiting."""
        resources = {
            "security_groups": [
                {
                    "id": "sg-wide",
                    "name": "wide-open",
                    "type": "security_group",
                    "raw": {
                        "ip_permissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 0,
                                "ToPort": 65535,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ]
                    },
                }
            ]
        }
        sg = evaluate(None, resources)["security_groups"][0]
        self.assertEqual(sg["status"], "CRITICAL")
        self.assertEqual({i["rule_id"] for i in sg["issues"]}, {"SG-002", "SG-003", "SG-004"})

    def test_ec2_stopped_and_imdsv1(self):
        resources = {
            "ec2_instances": [
                {
                    "id": "i-stopped",
                    "name": "old-box",
                    "type": "ec2_instance",
                    "raw": {"state": "stopped", "instance_type": "t3.micro", "http_tokens": "optional"},
                },
                {
                    "id": "i-healthy",
                    "name": "prod-box",
                    "type": "ec2_instance",
                    "raw": {"state": "running", "instance_type": "t3.small", "http_tokens": "required"},
                },
            ]
        }
        res = evaluate(None, resources)["ec2_instances"]
        self.assertEqual(res[0]["status"], "WARNING")
        self.assertEqual({i["rule_id"] for i in res[0]["issues"]}, {"EC2-001", "EC2-002"})
        self.assertEqual(res[1]["status"], "HEALTHY")
        self.assertEqual(res[1]["issues"], [])

    def test_rds_all_rules_and_missing_attribute_partial(self):
        resources = {
            "rds_instances": [
                {
                    "id": "db-risky",
                    "name": "db-risky",
                    "type": "rds_instance",
                    "raw": {
                        "engine": "postgres",
                        "publicly_accessible": True,
                        "storage_encrypted": False,
                        "deletion_protection": False,
                        "backup_retention_period": 0,
                    },
                },
                {
                    "id": "db-partial",
                    "name": "db-partial",
                    "type": "rds_instance",
                    "raw": {
                        "engine": "postgres",
                        "publicly_accessible": False,
                        "storage_encrypted": True,
                    },
                },
            ]
        }
        dbs = evaluate(None, resources)["rds_instances"]
        self.assertEqual(dbs[0]["status"], "CRITICAL")
        self.assertEqual({i["rule_id"] for i in dbs[0]["issues"]}, {"RDS-001", "RDS-002", "RDS-003", "RDS-004"})
        self.assertEqual(dbs[1]["status"], "NOT_ASSESSED")
        self.assertEqual(dbs[1]["assessment"]["status"], "PARTIAL")

    def test_ebs_and_orphan_snapshot_and_ebs_failure_guard(self):
        resources = {
            "ebs_volumes": [
                {"id": "vol-active", "name": "vol-active", "type": "ebs_volume", "region": "us-east-1", "raw": {"state": "in-use", "encrypted": True, "size": 20}},
                {"id": "vol-orphan", "name": "vol-orphan", "type": "ebs_volume", "region": "us-east-1", "raw": {"state": "available", "encrypted": False, "size": 50}},
            ],
            "snapshots": [
                {"id": "snap-ok", "name": "snap-ok", "type": "ebs_snapshot", "region": "us-east-1", "raw": {"volume_id": "vol-active"}},
                {"id": "snap-orphan", "name": "snap-orphan", "type": "ebs_snapshot", "region": "us-east-1", "raw": {"volume_id": "vol-deleted"}},
                {"id": "snap-unknown", "name": "snap-unknown", "type": "ebs_snapshot", "region": "eu-west-1", "raw": {"volume_id": "vol-eu"}},
            ],
        }
        scanner_statuses = [
            {"key": "ebs_volumes", "region": "us-east-1", "status": "COMPLETED"},
            {"key": "ebs_volumes", "region": "eu-west-1", "status": "FAILED"},
        ]
        res = evaluate(None, resources, scanner_statuses=scanner_statuses)
        self.assertEqual(res["ebs_volumes"][0]["status"], "HEALTHY")
        self.assertEqual(res["ebs_volumes"][1]["status"], "WARNING")
        self.assertEqual({i["rule_id"] for i in res["ebs_volumes"][1]["issues"]}, {"EBS-001", "EBS-002"})
        self.assertEqual(res["snapshots"][0]["status"], "HEALTHY")
        self.assertEqual(res["snapshots"][1]["status"], "ORPHANED")
        self.assertEqual(res["snapshots"][1]["issues"][0]["rule_id"], "SNAP-001")
        # Snapshots in regions where ebs_volumes failed must be NOT_ASSESSED, not falsely ORPHANED
        self.assertEqual(res["snapshots"][2]["status"], "NOT_ASSESSED")

    def test_dynamodb_encryption_and_empty_provisioned_cost_risk(self):
        resources = {
            "dynamodb_tables": [
                {
                    "id": "empty-prov",
                    "name": "empty-prov",
                    "type": "dynamodb_table",
                    "raw": {"sse_description": {"Status": "ENABLED", "SSEType": "AWS_OWNED"}, "billing_mode": "PROVISIONED", "item_count": 0},
                },
                {
                    "id": "ondemand-empty",
                    "name": "ondemand-empty",
                    "type": "dynamodb_table",
                    "raw": {"sse_description": {"Status": "ENABLED", "SSEType": "AWS_OWNED"}, "billing_mode": "PAY_PER_REQUEST", "item_count": 0},
                },
            ]
        }
        tables = evaluate(None, resources)["dynamodb_tables"]
        self.assertEqual(tables[0]["status"], "ORPHANED")
        self.assertEqual(tables[0]["issues"][0]["rule_id"], "DDB-002")
        self.assertEqual(tables[1]["status"], "HEALTHY")

    def test_iam_cross_account_vs_same_account_trust(self):
        resources = {
            "iam_roles": [
                {
                    "id": "AROA1",
                    "name": "same-account-role",
                    "type": "iam_role",
                    "raw": {
                        "role_name": "same-account-role",
                        "arn": "arn:aws:iam::111122223333:role/same-account-role",
                        "inline_policies": {},
                        "attached_managed_policies": [],
                        "trust_policy": {
                            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "sts:AssumeRole"}]
                        },
                    },
                },
                {
                    "id": "AROA2",
                    "name": "external-no-extid",
                    "type": "iam_role",
                    "raw": {
                        "role_name": "external-no-extid",
                        "arn": "arn:aws:iam::111122223333:role/external-no-extid",
                        "inline_policies": {},
                        "attached_managed_policies": [],
                        "trust_policy": {
                            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]
                        },
                    },
                },
            ]
        }
        roles = evaluate(None, resources, account_id="111122223333")["iam_roles"]
        self.assertEqual(roles[0]["status"], "HEALTHY")
        self.assertEqual(roles[1]["status"], "WARNING")
        self.assertEqual(roles[1]["issues"][0]["rule_id"], "IAM-008")

    def test_lambda_stale_and_deprecated_runtime_and_container_image(self):
        old_date = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        fresh_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        resources = {
            "lambda_functions": [
                {"id": "legacy-fn", "name": "legacy-fn", "type": "lambda_function", "raw": {"last_modified": old_date, "runtime": "python3.8", "package_type": "Zip"}},
                {"id": "img-fn", "name": "img-fn", "type": "lambda_function", "raw": {"last_modified": fresh_date, "runtime": None, "package_type": "Image"}},
            ]
        }
        fns = evaluate(None, resources)["lambda_functions"]
        self.assertEqual(fns[0]["status"], "WARNING")
        self.assertEqual({i["rule_id"] for i in fns[0]["issues"]}, {"LAM-001", "LAM-002"})
        self.assertEqual(fns[1]["status"], "HEALTHY")

    def test_nat_gateway_cost_risk_no_fake_dollar_amount_and_elb_classic(self):
        resources = {
            "nat_gateways": [
                {"id": "nat-1", "name": "nat-1", "type": "nat_gateway", "raw": {"state": "available", "subnet_id": "subnet-1"}}
            ],
            "load_balancers": [
                {"id": "old-elb", "name": "old-elb", "type": "load_balancer", "raw": {"scheme": "internet-facing", "type": "classic"}}
            ],
            "internet_gateways": [
                {"id": "igw-1", "name": "igw-1", "type": "internet_gateway", "raw": {"attachments": []}}
            ],
            "vpcs": [
                {"id": "vpc-1", "name": "vpc-1", "type": "vpc", "raw": {"is_default": True, "cidr_block": "172.31.0.0/16"}}
            ],
            "elastic_ips": [
                {"id": "eipalloc-1", "name": "1.2.3.4", "type": "elastic_ip", "raw": {"association_id": None, "public_ip": "1.2.3.4"}}
            ],
        }
        res = evaluate(None, resources)
        nat_issue = res["nat_gateways"][0]["issues"][0]
        self.assertEqual(nat_issue["rule_id"], "NAT-002")
        self.assertEqual(nat_issue["category"], "Cost Risk")
        self.assertNotIn("$", nat_issue["title"])
        self.assertNotIn("$", nat_issue["why"])

        self.assertEqual({i["rule_id"] for i in res["load_balancers"][0]["issues"]}, {"ELB-001", "ELB-002"})
        self.assertEqual(res["internet_gateways"][0]["status"], "ORPHANED")
        self.assertEqual(res["vpcs"][0]["status"], "WARNING")
        self.assertEqual(res["elastic_ips"][0]["status"], "ORPHANED")

    def test_s3_permission_error_marks_only_that_check_not_assessed(self):
        session = MagicMock()
        s3 = session.client.return_value
        s3.get_bucket_policy_status.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetBucketPolicyStatus"
        )
        s3.get_bucket_acl.return_value = {"Grants": []}
        s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "none"}},
            "GetBucketEncryption",
        )
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        resources = {
            "s3_buckets": [
                {"id": "bucket", "name": "bucket", "type": "s3_bucket", "raw": {"name": "bucket", "is_empty": False}}
            ]
        }
        bucket = evaluate(session, resources)["s3_buckets"][0]
        self.assertEqual(bucket["status"], "NOT_ASSESSED")
        self.assertEqual(bucket["assessment"]["status"], "PARTIAL")
        check = next(item for item in bucket["assessment"]["checks"] if item["rule_id"] == "S3-002")
        self.assertEqual(check["status"], "NOT_ASSESSED")
        self.assertIn("AccessDenied", check["reason"])

    def test_scanner_permission_failure_disclosed_as_partial_coverage(self):
        regional_modules = [
            "ec2", "ebs", "snapshots", "elastic_ip", "security_group",
            "vpcs", "internet_gateways", "nat_gateways", "load_balancers",
            "rds", "dynamodb_tables", "lambda_functions",
        ]
        session = MagicMock()
        session.client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
        discovered = {
            "id": "i-1",
            "name": "web",
            "type": "ec2_instance",
            "raw": {"state": "running", "http_tokens": "required"},
        }
        denied = ScannerError("AccessDenied after partial EC2 discovery", [discovered])

        with ExitStack() as stack:
            stack.enter_context(patch("lambda_handler.assume_role", return_value=session))
            stack.enter_context(patch("lambda_handler.validate_permissions", return_value={}))
            for name in regional_modules:
                scan_mock = stack.enter_context(patch.object(getattr(lambda_handler, name), "scan", return_value=[]))
                if name == "ec2":
                    scan_mock.side_effect = denied
            stack.enter_context(patch.object(lambda_handler.iam, "scan", return_value=[]))
            stack.enter_context(patch.object(lambda_handler.s3, "scan", return_value=[]))
            result = lambda_handler.run_scan("arn:aws:iam::123456789012:role/ReadOnly", ["us-east-1"])

        self.assertTrue(result["partial"])
        ec2_status = next(item for item in result["coverage"]["scanner_statuses"] if item["key"] == "ec2_instances")
        self.assertEqual(ec2_status["status"], "PARTIAL")
        self.assertEqual(ec2_status["count"], 1)
        self.assertIn("AccessDenied", ec2_status["reason"])
        self.assertEqual(result["resources"]["ec2_instances"][0]["id"], "i-1")
        self.assertEqual(len(result["coverage"]["rules_catalog"]), len(RULE_METADATA))


if __name__ == "__main__":
    unittest.main()
