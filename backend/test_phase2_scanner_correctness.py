"""Phase 2 Scanner Correctness, Remediation Safety & 12-Scenario Test Matrix.

All tests run strictly against mocks, synthetic AWS responses, and local fixtures.
Zero real AWS accounts or network endpoints are contacted.
"""

import collections
import datetime
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError, TokenRetrievalError

sys.path.insert(0, os.path.dirname(__file__))

import api_guard
import local_engine
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
    s3,
    security_group,
    snapshots,
    vpcs,
)
from scanner.misconfig import (
    RULE_METADATA,
    RULE_REMEDIATION_IMPACT,
    _extract_account_from_principal,
    _parse_datetime,
    evaluate,
    get_rules_catalog,
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _make_empty_session(regions=("us-east-1",), include_s3=False):
    """Build a synthetic boto3-like mock session with empty collections across all 10 services."""
    session = MagicMock()
    sts = MagicMock()
    sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:sts::123456789012:assumed-role/ClarityReadOnly/tester",
        "UserId": "AROA123:tester",
    }

    ec2_client = MagicMock()
    ec2_client.describe_regions.return_value = {
        "Regions": [{"RegionName": r} for r in regions]
    }
    ec2_client.describe_addresses.return_value = {"Addresses": []}
    ec2_client.get_paginator.return_value.paginate.return_value = []

    iam_client = MagicMock()
    iam_client.get_paginator.return_value.paginate.return_value = []

    lam_client = MagicMock()
    lam_client.get_paginator.return_value.paginate.return_value = []

    rds_client = MagicMock()
    rds_client.get_paginator.return_value.paginate.return_value = []

    ddb_client = MagicMock()
    ddb_client.list_tables.return_value = {"TableNames": []}

    cw_client = MagicMock()
    cw_client.get_paginator.return_value.paginate.return_value = []

    logs_client = MagicMock()
    logs_client.get_paginator.return_value.paginate.return_value = []

    ct_client = MagicMock()
    ct_client.describe_trails.return_value = {"trailList": []}

    s3_client = MagicMock()
    s3_client.list_buckets.return_value = {"Buckets": []}

    clients = {
        "sts": sts,
        "ec2": ec2_client,
        "iam": iam_client,
        "lambda": lam_client,
        "rds": rds_client,
        "dynamodb": ddb_client,
        "cloudwatch": cw_client,
        "logs": logs_client,
        "cloudtrail": ct_client,
        "s3": s3_client,
    }
    session.client.side_effect = lambda svc, **kw: clients[svc]
    return session, clients


class TestPhase2RuleCorrectnessAndRegressions(unittest.TestCase):
    def test_severity_distribution_and_remediation_impact_completeness(self):
        counts = collections.Counter(m["severity"] for m in RULE_METADATA.values())
        self.assertEqual(len(RULE_METADATA), 43)
        self.assertEqual(counts["CRITICAL"], 13)
        self.assertEqual(counts["WARNING"], 20)
        self.assertEqual(counts["UNUSED"], 3)
        self.assertEqual(counts["INFO"], 7)

        # Every rule in RULE_METADATA must have explicit remediation impact/consequence guidance
        self.assertEqual(set(RULE_REMEDIATION_IMPACT.keys()), set(RULE_METADATA.keys()))
        for rid, impact in RULE_REMEDIATION_IMPACT.items():
            self.assertTrue(len(impact) > 30, f"{rid} missing meaningful remediation impact text")

        # Catalog matches RULE_METADATA 1:1
        catalog = get_rules_catalog()
        self.assertEqual(len(catalog), 43)
        for item in catalog:
            self.assertEqual(item["severity"], RULE_METADATA[item["id"]]["severity"])

        # IAM policy & allowlist unchanged (28 default / 34 with S3)
        self.assertEqual(len(api_guard.get_allowed_iam_actions(include_s3=False)), 28)
        self.assertEqual(len(api_guard.get_allowed_iam_actions(include_s3=True)), 34)

    def test_security_group_protocol_normalization_and_omitted_tcp_ports(self):
        sgs = [
            # 1. TCP with omitted FromPort/ToPort (all TCP ports) -> must trigger SG-002, SG-003, SG-004
            {
                "id": "sg-all-tcp", "name": "all-tcp", "type": "security_group", "service": "EC2", "region": "us-east-1",
                "raw": {"ip_permissions": [{"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            },
            # 2. Numeric TCP protocol "6" on port 22 -> SG-002
            {
                "id": "sg-num-tcp", "name": "num-tcp", "type": "security_group", "service": "EC2", "region": "us-east-1",
                "raw": {"ip_permissions": [{"IpProtocol": "6", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]},
            },
            # 3. UDP-only on ports 22 & 5432 must NOT falsely trigger SSH (SG-002) or DB (SG-004),
            #    while UDP on 3389 DOES trigger RDP (SG-003).
            {
                "id": "sg-udp-ssh-db", "name": "udp-media", "type": "security_group", "service": "EC2", "region": "us-east-1",
                "raw": {"ip_permissions": [
                    {"IpProtocol": "udp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "17", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ]},
            },
            {
                "id": "sg-udp-rdp", "name": "udp-rdp", "type": "security_group", "service": "EC2", "region": "us-east-1",
                "raw": {"ip_permissions": [{"IpProtocol": "udp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            },
            # 4. Private CIDR only -> HEALTHY
            {
                "id": "sg-private", "name": "private", "type": "security_group", "service": "EC2", "region": "us-east-1",
                "raw": {"ip_permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]},
            },
        ]
        res = evaluate(None, {"security_groups": sgs})["security_groups"]
        self.assertEqual({i["rule_id"] for i in res[0]["issues"]}, {"SG-002", "SG-003", "SG-004"})
        self.assertEqual({i["rule_id"] for i in res[1]["issues"]}, {"SG-002"})
        self.assertEqual(res[2]["status"], "HEALTHY")
        self.assertEqual(res[2]["issues"], [])
        self.assertEqual({i["rule_id"] for i in res[3]["issues"]}, {"SG-003"})
        self.assertEqual(res[4]["status"], "HEALTHY")
        # Every finding includes impact/consequences
        for issue in res[0]["issues"]:
            self.assertTrue(issue.get("impact"))
            self.assertTrue(issue.get("fix"))
            self.assertTrue(issue.get("verify"))

    def test_iam_case_insensitivity_notresource_list_principal_and_negated_condition_bypasses(self):
        roles = [
            # 1. Mixed-case IAM:* with Null condition (negated condition must NOT bypass IAM-001!)
            {
                "id": "AROA-CASE", "name": "CaseAdmin", "type": "iam_role", "service": "IAM", "region": "global",
                "raw": {
                    "role_name": "CaseAdmin",
                    "arn": "arn:aws:iam::111122223333:role/CaseAdmin",
                    "is_service_linked": False,
                    "inline_policies": {
                        "p1": {
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "IAM:*",
                                "Resource": "*",
                                "Condition": {"Null": {"sts:ExternalId": True}},
                            }]
                        }
                    },
                    "attached_managed_policies": [],
                    "trust_policy": {"Statement": []},
                },
            },
            # 2. Allow + NotResource wildcard bypass on inline policy
            {
                "id": "AROA-NOTRES", "name": "NotResAdmin", "type": "iam_role", "service": "IAM", "region": "global",
                "raw": {
                    "role_name": "NotResAdmin",
                    "arn": "arn:aws:iam::111122223333:role/NotResAdmin",
                    "is_service_linked": False,
                    "inline_policies": {
                        "p1": {
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "s3:*",
                                "NotResource": ["[not-resource-excluded]"],
                            }]
                        }
                    },
                    "attached_managed_policies": [],
                    "trust_policy": {"Statement": []},
                },
            },
            # 3. List-wrapped Principal {"AWS": ["*"]} must trigger IAM-005
            {
                "id": "AROA-LISTPUB", "name": "ListPublic", "type": "iam_role", "service": "IAM", "region": "global",
                "raw": {
                    "role_name": "ListPublic",
                    "arn": "arn:aws:iam::111122223333:role/ListPublic",
                    "is_service_linked": False,
                    "inline_policies": {},
                    "attached_managed_policies": [],
                    "trust_policy": {
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": ["*"]},
                            "Condition": {"StringEqualsIfExists": {"aws:PrincipalOrgID": True}},
                        }]
                    },
                },
            },
            # 4. GovCloud cross-account trust with StringNotEquals must NOT bypass IAM-008
            {
                "id": "AROA-GOV", "name": "GovCross", "type": "iam_role", "service": "IAM", "region": "global",
                "raw": {
                    "role_name": "GovCross",
                    "arn": "arn:aws-us-gov:iam::111122223333:role/GovCross",
                    "is_service_linked": False,
                    "inline_policies": {},
                    "attached_managed_policies": [],
                    "trust_policy": {
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws-us-gov:iam::999988887777:root"},
                            "Condition": {"StringNotEquals": {"sts:ExternalId": True}},
                        }]
                    },
                },
            },
        ]
        res = evaluate(None, {"iam_roles": roles}, account_id="111122223333")["iam_roles"]
        self.assertIn("IAM-001", {i["rule_id"] for i in res[0]["issues"]})
        self.assertIn("IAM-006", {i["rule_id"] for i in res[1]["issues"]})
        self.assertIn("IAM-005", {i["rule_id"] for i in res[2]["issues"]})
        self.assertIn("IAM-008", {i["rule_id"] for i in res[3]["issues"]})
        # Verify GovCloud & STS principal account extraction
        self.assertEqual(_extract_account_from_principal("arn:aws-us-gov:iam::999988887777:root"), "999988887777")
        self.assertEqual(_extract_account_from_principal("arn:aws:sts::999988887777:assumed-role/Foo/bar"), "999988887777")

    def test_iam_user_boundaries_and_fail_closed_mfa_when_policies_denied(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        # 1. Exact 90-day boundary: 90 days passes, 91 days triggers IAM-010; Inactive 200d passes; missing date -> CHECK_FAILED
        users = [
            {
                "id": "AIDA-90", "name": "u90", "type": "iam_user", "service": "IAM", "region": "global",
                "raw": {
                    "user_name": "u90", "mfa_devices_count": 1, "attached_managed_policies": [], "inline_policies": {},
                    "access_keys": [
                        {"access_key_id": "AKIA90D", "status": "Active", "create_date": now - datetime.timedelta(days=90)},
                        {"access_key_id": "AKIAINACT", "status": "Inactive", "create_date": now - datetime.timedelta(days=200)},
                    ],
                },
            },
            {
                "id": "AIDA-91", "name": "u91", "type": "iam_user", "service": "IAM", "region": "global",
                "raw": {
                    "user_name": "u91", "mfa_devices_count": 1, "attached_managed_policies": [], "inline_policies": {},
                    "access_keys": [
                        {"access_key_id": "AKIA91D", "status": "Active", "create_date": now - datetime.timedelta(days=91)},
                    ],
                },
            },
            {
                "id": "AIDA-BADDATE", "name": "ubad", "type": "iam_user", "service": "IAM", "region": "global",
                "raw": {
                    "user_name": "ubad", "mfa_devices_count": 1, "attached_managed_policies": [], "inline_policies": {},
                    "access_keys": [
                        {"access_key_id": "AKIABAD", "status": "Active", "create_date": "not-a-date"},
                    ],
                },
            },
            {
                "id": "AIDA-IAMSTAR", "name": "uiamstar", "type": "iam_user", "service": "IAM", "region": "global",
                "raw": {
                    "user_name": "uiamstar", "mfa_devices_count": 0, "attached_managed_policies": [],
                    "inline_policies": {"p": {"Statement": [{"Effect": "Allow", "Action": "IAM:*", "Resource": "*"}]}},
                    "access_keys": [],
                },
            },
        ]
        res = evaluate(None, {"iam_users": users})["iam_users"]
        self.assertEqual(res[0]["status"], "HEALTHY")
        self.assertEqual({i["rule_id"] for i in res[1]["issues"]}, {"IAM-010"})
        self.assertEqual(res[2]["status"], "INCOMPLETE")
        self.assertTrue(any(c["rule_id"] == "IAM-010" and c["status"] == "CHECK_FAILED" for c in res[2]["assessment"]["checks"]))
        self.assertEqual({i["rule_id"] for i in res[3]["issues"]}, {"IAM-009", "IAM-011"})

        # 2. Collector fail-closed check: if list_attached_user_policies fails for non-console user with 0 MFA,
        # IAM-009 must be marked CHECK_FAILED instead of falsely PASSED.
        mock_iam = MagicMock()
        access_denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "ListAttachedUserPolicies")

        def _pag(op):
            p = MagicMock()
            if op == "list_users":
                p.paginate.return_value = [{"Users": [{"UserName": "svc-no-console", "UserId": "AIDA-X", "Arn": "arn:aws:iam::123456789012:user/svc-no-console"}]}]
            elif op == "list_mfa_devices":
                p.paginate.return_value = [{"MFADevices": []}]
            elif op == "list_access_keys":
                p.paginate.return_value = [{"AccessKeyMetadata": []}]
            elif op == "list_attached_user_policies":
                p.paginate.side_effect = access_denied
            elif op == "list_user_policies":
                p.paginate.return_value = [{"PolicyNames": []}]
            return p

        mock_iam.get_paginator.side_effect = _pag
        sess = MagicMock()
        sess.client.return_value = mock_iam
        scanned_users = iam.scan_users(sess)
        eval_u = evaluate(None, {"iam_users": scanned_users})["iam_users"][0]
        self.assertEqual(eval_u["status"], "INCOMPLETE")
        check_map = {c["rule_id"]: c["status"] for c in eval_u["assessment"]["checks"]}
        self.assertEqual(check_map["IAM-009"], "CHECK_FAILED")
        self.assertEqual(check_map["IAM-011"], "CHECK_FAILED")

    def test_vpc_001_marks_check_failed_when_ec2_or_rds_discovery_failed(self):
        vpcs_res = [{"id": "vpc-def", "name": "default", "type": "vpc", "service": "VPC", "region": "us-east-1", "raw": {"is_default": True, "cidr_block": "172.31.0.0/16"}}]
        statuses = [{"key": "ec2_instances", "region": "us-east-1", "status": "FAILED"}]
        evaluated = evaluate(None, {"vpcs": vpcs_res, "ec2_instances": [], "rds_instances": []}, scanner_statuses=statuses)["vpcs"][0]
        self.assertEqual(evaluated["status"], "INCOMPLETE")
        self.assertEqual(evaluated["assessment"]["checks"][0]["status"], "CHECK_FAILED")

    def test_datetime_parser_handles_naive_compact_offset_and_lambda_boundaries(self):
        # Naive timestamp must never raise TypeError during subtraction!
        dt_naive = _parse_datetime("2024-01-01T00:00:00")
        self.assertIsNotNone(dt_naive.tzinfo)
        dt_compact = _parse_datetime("2024-01-01T12:30:00.000+0000")
        self.assertIsNotNone(dt_compact)
        dt_offset_no_frac = _parse_datetime("2024-01-01T12:30:00+02:00")
        self.assertIsNotNone(dt_offset_no_frac)

        now = datetime.datetime.now(datetime.timezone.utc)
        fns = [
            # Exactly 90 days ago -> passes LAM-001; Image package with no runtime -> passes LAM-002
            {"id": "fn-90", "name": "fn-90", "type": "lambda_function", "service": "Lambda", "region": "us-east-1",
             "raw": {"last_modified": (now - datetime.timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S"), "package_type": "Image", "runtime": None}},
            # 91 days ago with naive timestamp -> INFO (LAM-001), deprecated runtime -> WARNING (LAM-002)
            {"id": "fn-91", "name": "fn-91", "type": "lambda_function", "service": "Lambda", "region": "us-east-1",
             "raw": {"last_modified": (now - datetime.timedelta(days=91)).strftime("%Y-%m-%dT%H:%M:%S"), "package_type": "Zip", "runtime": "python3.8"}},
        ]
        res = evaluate(None, {"lambda_functions": fns})["lambda_functions"]
        self.assertEqual(res[0]["status"], "HEALTHY")
        self.assertEqual(res[0]["issues"], [])
        self.assertEqual(res[1]["status"], "WARNING")
        self.assertEqual({i["rule_id"] for i in res[1]["issues"]}, {"LAM-001", "LAM-002"})


class TestPhase2RepresentativeAccountMatrix(unittest.TestCase):
    """12-scenario synthetic AWS account test matrix (zero real AWS calls)."""

    def test_01_empty_aws_account_and_ct000_scope(self):
        # All-regions empty account -> COMPLETE, 0 resources, S3 SKIPPED_OPTIONAL, CT-000 emitted
        sess, _ = _make_empty_session(regions=("us-east-1", "eu-west-1"))
        report = local_engine.run_local_scan(sess, regions="all", include_s3_checks=False)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(report["summary"]["total_resources"], 0)
        self.assertEqual(report["coverage"]["services_skipped_optional"], ["S3"])
        self.assertEqual(len(report["account_advisories"]), 1)
        self.assertEqual(report["account_advisories"][0]["rule_id"], "CT-000")
        self.assertTrue(report["account_advisories"][0].get("impact"))
        self.assertEqual(report["summary"]["finding_counts"]["critical"], 1)

        # Partial user-selected region scan -> MUST NOT falsely emit account-wide CT-000
        report_partial = local_engine.run_local_scan(sess, regions=["eu-west-1"], include_s3_checks=False)
        self.assertEqual(report_partial["status"], "COMPLETE")
        self.assertEqual(report_partial["account_advisories"], [])

    def test_02_small_personal_account(self):
        sess, clients = _make_empty_session(regions=("us-east-1",))
        clients["ec2"].get_paginator.side_effect = lambda op: _pag_returning(
            [{"Vpcs": [{"VpcId": "vpc-1", "IsDefault": True, "CidrBlock": "172.31.0.0/16", "State": "available"}]}] if op == "describe_vpcs"
            else [{"Reservations": [{"Instances": [{"InstanceId": "i-1", "InstanceType": "t3.micro", "State": {"Name": "running"}, "VpcId": "vpc-1", "MetadataOptions": {"HttpTokens": "required"}}]}]}] if op == "describe_instances"
            else []
        )
        clients["cloudtrail"].describe_trails.return_value = {
            "trailList": [{"Name": "acct-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/acct-trail", "HomeRegion": "us-east-1", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]
        }
        clients["cloudtrail"].get_trail_status.return_value = {"IsLogging": True}

        report = local_engine.run_local_scan(sess, regions="all", include_s3_checks=False)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(report["account_advisories"], [])
        self.assertEqual(report["summary"]["total_resources"], 3)
        self.assertEqual(report["summary"]["healthy"], 3)
        self.assertEqual(report["summary"]["critical_issues"], 0)

    def test_03_multi_region_account_with_cloudtrail_dedup(self):
        sess, clients = _make_empty_session(regions=("us-east-1", "eu-west-1", "ap-southeast-1"))
        # Same multi-region trail returned only in HomeRegion us-east-1
        clients["cloudtrail"].describe_trails.return_value = {
            "trailList": [{"Name": "global-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/global-trail", "HomeRegion": "us-east-1", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]
        }
        clients["cloudtrail"].get_trail_status.return_value = {"IsLogging": True}

        report = local_engine.run_local_scan(sess, regions="all", include_s3_checks=False)
        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(len(report["coverage"]["regions_scanned"]), 3)
        self.assertEqual(len(report["resources"]["cloudtrail_trails"]), 1)
        self.assertEqual(report["resources"]["cloudtrail_trails"][0]["region"], "us-east-1")

    def test_04_large_paginated_production_style_account(self):
        sess, clients = _make_empty_session(regions=("us-east-1",))
        # Multi-page EC2 (25 instances across 3 pages) & DynamoDB (2 pages)
        ec2_pages = [
            {"Reservations": [{"Instances": [
                {"InstanceId": f"i-{p}-{k}", "InstanceType": "m6i.large", "State": {"Name": "running"}, "MetadataOptions": {"HttpTokens": "required"}}
                for k in range(10)
            ]}]}
            for p in range(3)
        ]
        clients["ec2"].get_paginator.side_effect = lambda op: _pag_returning(ec2_pages if op == "describe_instances" else [])
        clients["dynamodb"].list_tables.side_effect = [
            {"TableNames": [f"tbl-{i}" for i in range(5)], "LastEvaluatedTableName": "tbl-4"},
            {"TableNames": [f"tbl-{i}" for i in range(5, 10)]},
        ]
        clients["dynamodb"].describe_table.side_effect = lambda TableName: {
            "Table": {"TableName": TableName, "TableArn": f"arn:aws:dynamodb:us-east-1:123456789012:table/{TableName}", "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"}, "ItemCount": 50}
        }
        report = local_engine.run_local_scan(sess, regions=["us-east-1"], include_s3_checks=False)
        self.assertEqual(len(report["resources"]["ec2_instances"]), 30)
        self.assertEqual(len(report["resources"]["dynamodb_tables"]), 10)
        self.assertEqual(report["status"], "COMPLETE")

    def test_05_restricted_iam_permissions_never_produce_false_healthy(self):
        sess, clients = _make_empty_session(regions=("us-east-1",))
        denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "Not authorized"}}, "DescribeDBInstances")
        clients["rds"].get_paginator.return_value.paginate.side_effect = denied
        report = local_engine.run_local_scan(sess, regions=["us-east-1"], include_s3_checks=False)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["summary"]["health_score_available"])
        rds_svc = next(s for s in report["coverage"]["service_summary"] if s["service"] == "RDS")
        self.assertEqual(rds_svc["status"], "INCOMPLETE")
        self.assertTrue(any(f["service"] == "RDS" for f in report["coverage"]["failures"]))

    def test_06_expired_credentials_surface_clean_error_without_secret_leak(self):
        sess = MagicMock()
        sts = MagicMock()
        sts.get_caller_identity.side_effect = TokenRetrievalError(provider="sso", error_msg="Token expired")
        sess.client.return_value = sts
        with self.assertRaises(RuntimeError) as ctx:
            local_engine.verify_identity(sess)
        self.assertIn("aws sso login", str(ctx.exception))

        sts2 = MagicMock()
        sts2.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "ExpiredToken", "Message": "SessionToken=SECRETTOKEN999 expired"}}, "GetCallerIdentity"
        )
        sess.client.return_value = sts2
        with self.assertRaises(RuntimeError) as ctx2:
            local_engine.verify_identity(sess)
        self.assertIn("ExpiredToken", str(ctx2.exception))
        self.assertNotIn("SECRETTOKEN999", str(ctx2.exception))

    def test_07_inaccessible_region_identified_in_regions_failed(self):
        import boto3
        real_sess = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1")
        with patch("local_engine.verify_identity", return_value={"account_id": "123456789012", "caller_arn": "arn:aws:sts::123456789012:assumed-role/RO/t", "user_id": "A:t"}), \
             patch("local_engine.discover_enabled_regions", return_value=(["me-south-1", "us-east-1"], {"mode": "auto_discovered", "status": "COMPLETE", "count": 2})), \
             patch("lambda_handler._probe_region_endpoint", side_effect=lambda reg, timeout=3.0: (False, "connect timed out") if reg == "me-south-1" else (True, None)), \
             patch("scanner.iam.scan_roles", return_value=[]), \
             patch("scanner.iam.scan_users", return_value=[]), \
             patch("lambda_handler._get_regional_scanners", return_value={
                 "ec2_instances": lambda s, r: [], "cloudtrail_trails": lambda s, r: [],
             }):
            report = local_engine.run_local_scan(real_sess, regions="all", include_s3_checks=False)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["summary"]["health_score_available"])
        self.assertEqual(report["coverage"]["regions_failed"], ["me-south-1"])
        self.assertEqual(report["coverage"]["regions_succeeded"], ["us-east-1"])
        # Because me-south-1 failed CloudTrail, CT-000 must NOT falsely fire
        self.assertEqual(report["account_advisories"], [])

    def test_08_optional_s3_enabled_and_disabled(self):
        sess, clients = _make_empty_session(regions=("us-east-1",))
        clients["s3"].list_buckets.return_value = {"Buckets": [{"Name": "corp-bucket"}]}
        clients["s3"].get_bucket_location.return_value = {"LocationConstraint": None}
        clients["s3"].get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
        clients["s3"].get_bucket_acl.return_value = {"Grants": []}
        clients["s3"].get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "Default SSE-S3"}},
            "GetBucketEncryption",
        )
        clients["s3"].get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }

        # Disabled (default): S3 SKIPPED_OPTIONAL, 0 S3 calls
        rep_off = local_engine.run_local_scan(sess, regions=["us-east-1"], include_s3_checks=False)
        clients["s3"].list_buckets.assert_not_called()
        s3_off = next(s for s in rep_off["coverage"]["service_summary"] if s["service"] == "S3")
        self.assertEqual(s3_off["status"], "SKIPPED_OPTIONAL")

        # Enabled with consent: S3 COMPLETE, bucket HEALTHY (S3-004 default encryption passes)
        rep_on = local_engine.run_local_scan(sess, regions=["us-east-1"], include_s3_checks=True, confirm_s3_request_costs=True)
        clients["s3"].list_buckets.assert_called_once()
        s3_on = next(s for s in rep_on["coverage"]["service_summary"] if s["service"] == "S3")
        self.assertEqual(s3_on["status"], "COMPLETE")
        self.assertEqual(rep_on["resources"]["s3_buckets"][0]["status"], "HEALTHY")

    def test_09_unusual_tags_and_descriptions_sanitized_without_crashing(self):
        sess, clients = _make_empty_session(regions=("us-east-1",))
        clients["ec2"].get_paginator.side_effect = lambda op: _pag_returning(
            [{"Reservations": [{"Instances": [{
                "InstanceId": "i-weird",
                "InstanceType": "t3.nano",
                "State": {"Name": "running"},
                "MetadataOptions": {"HttpTokens": "required"},
                "Tags": [
                    {"Key": "Name", "Value": "=CMD|'x'!A0\x00\x07<script>alert(1)</script>"},
                    {"Key": "Secret", "Value": "SHOULD_BE_DROPPED_TAG"},
                ],
            }]}]}] if op == "describe_instances" else []
        )
        report = local_engine.run_local_scan(sess, regions=["us-east-1"], include_s3_checks=False)
        inst = report["resources"]["ec2_instances"][0]
        self.assertEqual(inst["status"], "HEALTHY")
        self.assertNotIn("\x00", inst["name"])
        self.assertNotIn("SHOULD_BE_DROPPED_TAG", json.dumps(report, default=str))

    def test_10_missing_or_unusual_config_values_fail_closed(self):
        evaluated = evaluate(None, {
            "ec2_instances": [{"id": "i-no-imds", "name": "no-imds", "type": "ec2_instance", "service": "EC2", "region": "us-east-1", "raw": {"state": "running", "http_tokens": None}}],
            "lambda_functions": [{"id": "fn-no-rt", "name": "no-rt", "type": "lambda_function", "service": "Lambda", "region": "us-east-1", "raw": {"package_type": "Zip", "runtime": None, "last_modified": "invalid-ts"}}],
            "dynamodb_tables": [{"id": "t-no-sse", "name": "t-no-sse", "type": "dynamodb_table", "service": "DynamoDB", "region": "us-east-1", "raw": {"billing_mode": "PAY_PER_REQUEST", "item_count": 1, "sse_description": {}}}],
        })
        self.assertEqual(evaluated["ec2_instances"][0]["status"], "INCOMPLETE")
        self.assertEqual(evaluated["lambda_functions"][0]["status"], "INCOMPLETE")
        self.assertEqual(evaluated["dynamodb_tables"][0]["status"], "INCOMPLETE")

    def test_11_legitimate_resources_triggering_heuristic_info_stay_healthy(self):
        old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=180)).isoformat()
        evaluated = evaluate(None, {
            "ec2_instances": [{"id": "i-dev", "name": "dev-paused", "type": "ec2_instance", "service": "EC2", "region": "us-east-1", "raw": {"state": "stopped", "http_tokens": "required"}}],
            "nat_gateways": [{"id": "nat-prod", "name": "prod-nat", "type": "nat_gateway", "service": "VPC", "region": "us-east-1", "raw": {"state": "available", "subnet_id": "subnet-1"}}],
            "lambda_functions": [{"id": "fn-stable", "name": "stable", "type": "lambda_function", "service": "Lambda", "region": "us-east-1", "raw": {"last_modified": old_ts, "runtime": "python3.12"}}],
            "dynamodb_tables": [{"id": "tbl-free", "name": "free-tier", "type": "dynamodb_table", "service": "DynamoDB", "region": "us-east-1", "raw": {"billing_mode": "PROVISIONED", "item_count": 0, "sse_description": {"Status": "ENABLED"}}}],
            "ebs_volumes": [],
            "snapshots": [{"id": "snap-ami", "name": "ami-snap", "type": "ebs_snapshot", "service": "EBS", "region": "us-east-1", "raw": {"volume_id": "vol-orig", "volume_size": 20}}],
            "cloudwatch_alarms": [{"id": "al-sparse", "name": "sparse", "type": "cloudwatch_alarm", "service": "CloudWatch", "region": "us-east-1", "raw": {"actions_enabled": True, "state_value": "INSUFFICIENT_DATA"}}],
        })
        for grp in ("ec2_instances", "nat_gateways", "lambda_functions", "dynamodb_tables", "snapshots", "cloudwatch_alarms"):
            r = evaluated[grp][0]
            self.assertEqual(r["status"], "HEALTHY", f"Heuristic INFO rule on {grp} must not mark resource unhealthy")
            self.assertEqual([i["severity"] for i in r["issues"]], ["INFO"])

    def test_12_zero_resource_services_remain_complete_distinct_from_skipped_or_failed(self):
        sess, _ = _make_empty_session(regions=("us-east-1",))
        report = local_engine.run_local_scan(sess, regions=["us-east-1"], include_s3_checks=False)
        by_svc = {s["service"]: s for s in report["coverage"]["service_summary"]}
        for svc in ("EC2", "VPC", "IAM", "Lambda", "RDS", "DynamoDB", "EBS", "CloudWatch", "CloudTrail"):
            self.assertEqual(by_svc[svc]["status"], "COMPLETE")
            self.assertEqual(by_svc[svc]["resource_count"], 0)
        self.assertEqual(by_svc["S3"]["status"], "SKIPPED_OPTIONAL")


def _pag_returning(pages):
    p = MagicMock()
    p.paginate.return_value = pages
    return p


if __name__ == "__main__":
    unittest.main()
