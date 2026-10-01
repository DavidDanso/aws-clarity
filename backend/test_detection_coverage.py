import unittest
import datetime
import os
import sys
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from contextlib import ExitStack
from exceptions import ScannerError

sys.path.insert(0, os.path.dirname(__file__))
from scanner.misconfig import evaluate


class TestDetectionCoverage(unittest.TestCase):

    def test_ecr_problematic_configuration(self):
        """ECR repository with mutable tags and disabled scanning should produce ECR-001 and ECR-002 (WARNING)."""
        resources = {
            "ecr_repositories": [
                {
                    "id": "app-repo",
                    "name": "app-repo",
                    "type": "ecr_repository",
                    "status": "HEALTHY",
                    "raw": {
                        "repository_arn": "arn:aws:ecr:us-east-1:123456789012:repository/app-repo",
                        "image_tag_mutability": "MUTABLE",
                        "image_tag_mutability_exclusion_filters": [],
                        "image_scanning_configuration": {"scanOnPush": False},
                        "scan_frequency": "MANUAL",
                        "applied_scan_filters": [],
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        repo = res["ecr_repositories"][0]
        self.assertEqual(repo["status"], "WARNING")
        self.assertEqual(len(repo["issues"]), 2)
        rule_ids = {i["rule_id"] for i in repo["issues"]}
        self.assertEqual(rule_ids, {"ECR-001", "ECR-002"})
        
        # Verify explainable evidence fields
        ecr001 = next(i for i in repo["issues"] if i["rule_id"] == "ECR-001")
        self.assertEqual(ecr001["evidence"]["Repository"], "app-repo")
        self.assertEqual(ecr001["evidence"]["ImageTagMutability"], "MUTABLE")
        self.assertIn("immutable", ecr001["fix"])
        self.assertEqual(ecr001["resource_type"], "ecr_repository")
        self.assertEqual(ecr001["resource_id"], "app-repo")
        self.assertEqual(ecr001["category"], "Security")
        self.assertEqual(ecr001["source"], "AWS API configuration")
        self.assertEqual(repo["assessment"]["status"], "ASSESSED")

    def test_ecr_healthy_configuration(self):
        """ECR repository with immutable tags and scanOnPush enabled should be HEALTHY."""
        resources = {
            "ecr_repositories": [
                {
                    "id": "secure-repo",
                    "name": "secure-repo",
                    "type": "ecr_repository",
                    "status": "HEALTHY",
                    "raw": {
                        "repository_arn": "arn:aws:ecr:us-east-1:123456789012:repository/secure-repo",
                        "image_tag_mutability": "IMMUTABLE",
                        "image_tag_mutability_exclusion_filters": [],
                        "image_scanning_configuration": {"scanOnPush": True},
                        "scan_frequency": "CONTINUOUS_SCAN",
                        "applied_scan_filters": [{"filter": "*", "filterType": "WILDCARD"}],
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        repo = res["ecr_repositories"][0]
        self.assertEqual(repo["status"], "HEALTHY")
        self.assertEqual(len(repo["issues"]), 0)

    def test_ecr_missing_effective_scan_configuration_is_not_assessed(self):
        resources = {"ecr_repositories": [{
            "id": "unknown-repo", "name": "unknown-repo", "type": "ecr_repository",
            "raw": {"image_tag_mutability": "IMMUTABLE", "scan_frequency": None},
        }]}
        repo = evaluate(None, resources)["ecr_repositories"][0]
        self.assertEqual(repo["status"], "NOT_ASSESSED")
        self.assertEqual(repo["assessment"]["status"], "PARTIAL")
        self.assertEqual(repo["assessment"]["checks"][1]["status"], "NOT_ASSESSED")
        self.assertEqual(repo["issues"], [])

    def test_ecr_null_tag_mutability_is_not_reported_as_healthy(self):
        resources = {"ecr_repositories": [{
            "id": "unknown-tags", "name": "unknown-tags", "type": "ecr_repository",
            "raw": {"image_tag_mutability": None, "scan_frequency": "SCAN_ON_PUSH"},
        }]}
        repo = evaluate(None, resources)["ecr_repositories"][0]
        self.assertEqual(repo["status"], "NOT_ASSESSED")
        self.assertEqual(repo["assessment"]["checks"][0]["status"], "NOT_ASSESSED")
        self.assertEqual(repo["issues"], [])

    def test_ecr_enhanced_continuous_scanning_passes(self):
        resources = {"ecr_repositories": [{
            "id": "enhanced-repo", "name": "enhanced-repo", "type": "ecr_repository",
            "raw": {
                "image_tag_mutability": "IMMUTABLE",
                "image_tag_mutability_exclusion_filters": [],
                "scan_frequency": "CONTINUOUS_SCAN",
                "applied_scan_filters": [{"filter": "*", "filterType": "WILDCARD"}],
            },
        }]}
        repo = evaluate(None, resources)["ecr_repositories"][0]
        self.assertEqual(repo["status"], "HEALTHY")
        self.assertEqual(repo["assessment"]["status"], "ASSESSED")

    def test_ecr_exclusion_mutability_is_reported(self):
        resources = {"ecr_repositories": [{
            "id": "filtered-repo", "name": "filtered-repo", "type": "ecr_repository",
            "raw": {
                "image_tag_mutability": "IMMUTABLE_WITH_EXCLUSION",
                "image_tag_mutability_exclusion_filters": [{"filterType": "WILDCARD", "filter": "latest"}],
                "scan_frequency": "SCAN_ON_PUSH",
            },
        }]}
        repo = evaluate(None, resources)["ecr_repositories"][0]
        self.assertEqual(repo["status"], "WARNING")
        self.assertEqual(repo["issues"][0]["rule_id"], "ECR-001")

    def test_eks_public_endpoint(self):
        """EKS cluster with public endpoint open to 0.0.0.0/0 should be CRITICAL (EKS-001)."""
        resources = {
            "eks_clusters": [
                {
                    "id": "prod-cluster",
                    "name": "prod-cluster",
                    "type": "eks_cluster",
                    "status": "HEALTHY",
                    "raw": {
                        "resources_vpc_config": {
                            "endpointPublicAccess": True,
                            "publicAccessCidrs": ["0.0.0.0/0"],
                        }
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        cluster = res["eks_clusters"][0]
        self.assertEqual(cluster["status"], "CRITICAL")
        self.assertEqual(len(cluster["issues"]), 1)
        self.assertEqual(cluster["issues"][0]["rule_id"], "EKS-001")

    def test_redshift_public_and_unencrypted(self):
        """Redshift cluster publicly accessible and unencrypted should be CRITICAL (RS-001, RS-002)."""
        resources = {
            "redshift_clusters": [
                {
                    "id": "analytics-cluster",
                    "name": "analytics-cluster",
                    "type": "redshift_cluster",
                    "status": "HEALTHY",
                    "raw": {
                        "publicly_accessible": True,
                        "encrypted": False,
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        cluster = res["redshift_clusters"][0]
        self.assertEqual(cluster["status"], "CRITICAL")
        self.assertEqual(len(cluster["issues"]), 2)
        rule_ids = {i["rule_id"] for i in cluster["issues"]}
        self.assertEqual(rule_ids, {"RS-001", "RS-002"})

    def test_aurora_unencrypted_no_deletion_protection(self):
        """Aurora cluster with unencrypted storage and no deletion protection should produce AUR-001 and AUR-002 (WARNING)."""
        resources = {
            "aurora_clusters": [
                {
                    "id": "aurora-db",
                    "name": "aurora-db",
                    "type": "aurora_cluster",
                    "status": "HEALTHY",
                    "raw": {
                        "storage_encrypted": False,
                        "deletion_protection": False,
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        cluster = res["aurora_clusters"][0]
        self.assertEqual(cluster["status"], "WARNING")
        rule_ids = {i["rule_id"] for i in cluster["issues"]}
        self.assertEqual(rule_ids, {"AUR-001", "AUR-002"})

    def test_nat_gateway_cost_risk_no_dollar_amount(self):
        """Active NAT gateway should trigger NAT-002 with configuration cost risk, never hardcoded dollar amount."""
        resources = {
            "nat_gateways": [
                {
                    "id": "nat-012345",
                    "name": "nat-012345",
                    "type": "nat_gateway",
                    "status": "HEALTHY",
                    "raw": {
                        "state": "available",
                        "subnet_id": "subnet-0abc",
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        nat = res["nat_gateways"][0]
        self.assertEqual(nat["status"], "WARNING")
        self.assertEqual(len(nat["issues"]), 1)
        issue = nat["issues"][0]
        self.assertEqual(issue["rule_id"], "NAT-002")
        self.assertEqual(issue["category"], "Cost Risk")
        # Ensure no fake dollar cost is stated in title or why
        self.assertNotIn("$", issue["title"])
        self.assertNotIn("$", issue["why"])

    def test_auto_scaling_group_dormant_orphan(self):
        """Auto Scaling Group with desired=0 and min=0 should be marked ORPHANED (ASG-001)."""
        resources = {
            "auto_scaling_groups": [
                {
                    "id": "dormant-asg",
                    "name": "dormant-asg",
                    "type": "auto_scaling_group",
                    "status": "HEALTHY",
                    "raw": {
                        "desired_capacity": 0,
                        "min_size": 0,
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        asg = res["auto_scaling_groups"][0]
        self.assertEqual(asg["status"], "ORPHANED")
        self.assertEqual(asg["issues"][0]["rule_id"], "ASG-001")

    def test_ecs_cluster_empty_orphan(self):
        """ECS cluster with 0 instances and 0 active services should be ORPHANED (ECS-001)."""
        resources = {
            "ecs_clusters": [
                {
                    "id": "arn:aws:ecs:us-east-1:123456789012:cluster/empty-cluster",
                    "name": "empty-cluster",
                    "type": "ecs_cluster",
                    "status": "HEALTHY",
                    "raw": {
                        "registered_container_instances_count": 0,
                        "active_services_count": 0,
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        ecs = res["ecs_clusters"][0]
        self.assertEqual(ecs["status"], "ORPHANED")
        self.assertEqual(ecs["issues"][0]["rule_id"], "ECS-001")

    def test_internet_gateway_unattached_orphan(self):
        """Internet Gateway with no attachments should be ORPHANED (IGW-001)."""
        resources = {
            "internet_gateways": [
                {
                    "id": "igw-012345",
                    "name": "igw-012345",
                    "type": "internet_gateway",
                    "status": "HEALTHY",
                    "raw": {
                        "attachments": [],
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        igw = res["internet_gateways"][0]
        self.assertEqual(igw["status"], "ORPHANED")
        self.assertEqual(igw["issues"][0]["rule_id"], "IGW-001")

    def test_unassessed_resource_becomes_not_assessed(self):
        """API Gateways (and any unassessed resource type) must NOT silently become HEALTHY."""
        resources = {
            "api_gateways": [
                {
                    "id": "api-123",
                    "name": "my-api",
                    "type": "api_gateway",
                    "status": "HEALTHY",
                    "raw": {
                        "protocol_type": "HTTP",
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        api = res["api_gateways"][0]
        self.assertEqual(api["status"], "NOT_ASSESSED")
        self.assertEqual(len(api["issues"]), 0)

    def test_missing_or_empty_raw_configuration(self):
        """Resources with missing or empty raw attributes must become NOT_ASSESSED, not falsely HEALTHY."""
        resources = {
            "ecr_repositories": [
                {
                    "id": "unknown-repo",
                    "name": "unknown-repo",
                    "type": "ecr_repository",
                    "status": "HEALTHY",
                    "raw": {},
                }
            ]
        }
        res = evaluate(None, resources)
        repo = res["ecr_repositories"][0]
        self.assertEqual(repo["status"], "NOT_ASSESSED")
        self.assertEqual(len(repo["issues"]), 0)
        self.assertEqual(repo["assessment"]["status"], "NOT_ASSESSED")

    def test_missing_rule_attribute_does_not_become_healthy(self):
        resources = {"rds_instances": [{
            "id": "db-1", "name": "db-1", "type": "rds_instance",
            "raw": {"publicly_accessible": False, "storage_encrypted": True},
        }]}
        db = evaluate(None, resources)["rds_instances"][0]
        self.assertEqual(db["status"], "NOT_ASSESSED")
        self.assertEqual(db["assessment"]["status"], "PARTIAL")

    def test_finding_status_survives_other_unassessed_check(self):
        resources = {"rds_instances": [{
            "id": "db-1", "name": "db-1", "type": "rds_instance",
            "raw": {"publicly_accessible": True, "storage_encrypted": True},
        }]}
        db = evaluate(None, resources)["rds_instances"][0]
        self.assertEqual(db["status"], "CRITICAL")
        self.assertEqual(db["assessment"]["status"], "PARTIAL")
        self.assertEqual(db["issues"][0]["resource_id"], "db-1")

    def test_unchecked_resource_type_is_not_assessed(self):
        resources = {"unsupported_group": [{"id": "x", "name": "x", "raw": {"value": True}}]}
        result = evaluate(None, resources)["unsupported_group"][0]
        self.assertEqual(result["status"], "NOT_ASSESSED")
        self.assertEqual(result["assessment"]["checks"], [])

    def test_ecr_scanner_uses_effective_batch_scan_frequency(self):
        from scanner.ecr_repositories import scan
        session = MagicMock()
        client = session.client.return_value
        client.get_paginator.return_value.paginate.return_value = [{"repositories": [{
            "repositoryName": "repo", "repositoryArn": "arn:repo", "imageTagMutability": "IMMUTABLE",
            "imageScanningConfiguration": {"scanOnPush": False},
        }]}]
        client.batch_get_repository_scanning_configuration.return_value = {
            "scanningConfigurations": [{"repositoryName": "repo", "scanFrequency": "CONTINUOUS_SCAN", "appliedScanFilters": []}],
            "failures": [],
        }
        result = scan(session)[0]
        self.assertEqual(result["raw"]["scan_frequency"], "CONTINUOUS_SCAN")
        self.assertEqual(result["raw"]["image_scanning_configuration"]["scanOnPush"], False)
        client.batch_get_repository_scanning_configuration.assert_called_once_with(repositoryNames=["repo"])

    def test_ecr_scanner_discloses_per_repository_configuration_failure(self):
        from scanner.ecr_repositories import scan
        session = MagicMock()
        client = session.client.return_value
        client.get_paginator.return_value.paginate.return_value = [{"repositories": [{
            "repositoryName": "repo", "imageTagMutability": "IMMUTABLE",
        }]}]
        client.batch_get_repository_scanning_configuration.return_value = {
            "scanningConfigurations": [],
            "failures": [{"repositoryName": "repo", "failureReason": "denied"}],
        }
        result = scan(session)[0]
        self.assertIn("ECR-002", result["assessment_errors"])

    def test_ecr_scanner_preserves_discovery_when_scan_configuration_api_is_denied(self):
        from scanner.ecr_repositories import scan
        session = MagicMock()
        client = session.client.return_value
        client.get_paginator.return_value.paginate.return_value = [{"repositories": [{
            "repositoryName": "repo", "imageTagMutability": "IMMUTABLE",
        }]}]
        client.batch_get_repository_scanning_configuration.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "BatchGetRepositoryScanningConfiguration",
        )
        result = scan(session)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "repo")
        self.assertIn("ECR-002", result[0]["assessment_errors"])

    def test_scanner_permission_failure_is_disclosed_as_partial_coverage(self):
        import lambda_handler
        regional_modules = [
            "ec2", "ebs", "elastic_ip", "security_group", "snapshots", "rds",
            "lambda_functions", "nat_gateways", "load_balancers", "dynamodb_tables",
            "vpcs", "auto_scaling_groups", "ecs_clusters", "eks_clusters",
            "elasticache_clusters", "sqs_queues", "sns_topics", "secrets_manager",
            "api_gateways", "aurora_clusters", "cloudformation_stacks", "eventbridge_rules",
            "ecr_repositories", "internet_gateways", "cloudwatch_alarms", "redshift_clusters",
        ]
        session = MagicMock()
        session.client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}
        discovered = {"id": "i-1", "name": "web", "type": "ec2_instance", "raw": {"state": "running"}}
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
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }}
        resources = {"s3_buckets": [{
            "id": "bucket", "name": "bucket", "type": "s3_bucket",
            "raw": {"name": "bucket", "is_empty": False},
        }]}
        bucket = evaluate(session, resources)["s3_buckets"][0]
        self.assertEqual(bucket["status"], "NOT_ASSESSED")
        self.assertEqual(bucket["assessment"]["status"], "PARTIAL")
        check = next(item for item in bucket["assessment"]["checks"] if item["rule_id"] == "S3-002")
        self.assertEqual(check["status"], "NOT_ASSESSED")
        self.assertIn("AccessDenied", check["reason"])

    def test_unrelated_resources_unaffected(self):
        """Existing Security Group and S3 checks evaluate accurately alongside new rules."""
        resources = {
            "security_groups": [
                {
                    "id": "sg-1",
                    "name": "open-ssh",
                    "type": "security_group",
                    "status": "HEALTHY",
                    "raw": {
                        "ip_permissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ]
                    },
                }
            ],
            "ec2_instances": [
                {
                    "id": "i-12345",
                    "name": "stopped-inst",
                    "type": "ec2_instance",
                    "status": "HEALTHY",
                    "raw": {
                        "state": "stopped",
                        "instance_type": "t3.medium",
                    },
                }
            ],
        }
        res = evaluate(None, resources)
        self.assertEqual(res["security_groups"][0]["status"], "CRITICAL")
        self.assertEqual(res["security_groups"][0]["issues"][0]["rule_id"], "SG-002")
        self.assertEqual(res["ec2_instances"][0]["status"], "ORPHANED")
        self.assertEqual(res["ec2_instances"][0]["issues"][0]["rule_id"], "EC2-001")


    def test_elasticache_encryption(self):
        """ElastiCache without at-rest or transit encryption triggers EC-001 and EC-002."""
        resources = {
            "elasticache_clusters": [
                {
                    "id": "cache-01",
                    "name": "cache-01",
                    "type": "elasticache_cluster",
                    "status": "HEALTHY",
                    "raw": {
                        "at_rest_encryption_enabled": False,
                        "transit_encryption_enabled": False,
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        c = res["elasticache_clusters"][0]
        self.assertEqual(c["status"], "WARNING")
        rule_ids = {i["rule_id"] for i in c["issues"]}
        self.assertEqual(rule_ids, {"EC-001", "EC-002"})

    def test_dynamodb_kms_encryption(self):
        """An explicit DynamoDB SSE disabled state triggers DDB-001."""
        resources = {
            "dynamodb_tables": [
                {
                    "id": "users-table",
                    "name": "users-table",
                    "type": "dynamodb_table",
                    "status": "HEALTHY",
                    "raw": {
                        "table_status": "ACTIVE",
                        "sse_description": {"Status": "DISABLED"},
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        tbl = res["dynamodb_tables"][0]
        self.assertEqual(tbl["status"], "WARNING")
        self.assertEqual(tbl["issues"][0]["rule_id"], "DDB-001")

    def test_secrets_manager_rotation_and_kms(self):
        """Secret with disabled rotation and default key triggers SEC-001 and SEC-002."""
        resources = {
            "secrets": [
                {
                    "id": "app-api-key",
                    "name": "app-api-key",
                    "type": "secret",
                    "status": "HEALTHY",
                    "raw": {
                        "rotation_enabled": False,
                        "kms_key_id": None,
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        s = res["secrets"][0]
        self.assertEqual(s["status"], "WARNING")
        rule_ids = {i["rule_id"] for i in s["issues"]}
        self.assertEqual(rule_ids, {"SEC-001", "SEC-002"})

    def test_sqs_and_sns_encryption(self):
        """SQS queue and SNS topic without KMS trigger SQS-001 and SNS-001."""
        resources = {
            "sqs_queues": [
                {
                    "id": "orders-queue",
                    "name": "orders-queue",
                    "type": "sqs_queue",
                    "status": "HEALTHY",
                    "raw": {"kms_master_key_id": None, "sqs_managed_sse_enabled": False},
                }
            ],
            "sns_topics": [
                {
                    "id": "alerts-topic",
                    "name": "alerts-topic",
                    "type": "sns_topic",
                    "status": "HEALTHY",
                    "raw": {"kms_master_key_id": None},
                }
            ],
        }
        res = evaluate(None, resources)
        self.assertEqual(res["sqs_queues"][0]["issues"][0]["rule_id"], "SQS-001")
        self.assertEqual(res["sns_topics"][0]["issues"][0]["rule_id"], "SNS-001")

    def test_sqs_sqs_managed_encryption_passes_without_kms_key(self):
        resources = {"sqs_queues": [{
            "id": "encrypted-queue", "name": "encrypted-queue", "type": "sqs_queue",
            "raw": {"kms_master_key_id": None, "sqs_managed_sse_enabled": "true"},
        }]}
        queue = evaluate(None, resources)["sqs_queues"][0]
        self.assertEqual(queue["status"], "HEALTHY")
        self.assertEqual(queue["assessment"]["checks"][0]["status"], "PASSED")

    def test_sqs_missing_encryption_attributes_is_not_assessed(self):
        resources = {"sqs_queues": [{
            "id": "unknown-queue", "name": "unknown-queue", "type": "sqs_queue",
            "raw": {"kms_master_key_id": None, "sqs_managed_sse_enabled": None},
        }]}
        queue = evaluate(None, resources)["sqs_queues"][0]
        self.assertEqual(queue["status"], "NOT_ASSESSED")
        self.assertEqual(queue["issues"], [])

    def test_dynamodb_missing_sse_status_is_not_assessed(self):
        resources = {"dynamodb_tables": [{
            "id": "unknown-table", "name": "unknown-table", "type": "dynamodb_table",
            "raw": {"sse_description": {}},
        }]}
        table = evaluate(None, resources)["dynamodb_tables"][0]
        self.assertEqual(table["status"], "NOT_ASSESSED")
        self.assertEqual(table["issues"], [])

    def test_cloudwatch_and_eventbridge(self):
        """CloudWatch alarms and EventBridge rules trigger CW-001, CW-002, EV-001."""
        resources = {
            "cloudwatch_alarms": [
                {
                    "id": "cpu-high",
                    "name": "cpu-high",
                    "type": "cloudwatch_alarm",
                    "status": "HEALTHY",
                    "raw": {
                        "actions_enabled": False,
                        "state_value": "INSUFFICIENT_DATA",
                    },
                }
            ],
            "eventbridge_rules": [
                {
                    "id": "nightly-cleanup",
                    "name": "nightly-cleanup",
                    "type": "eventbridge_rule",
                    "status": "HEALTHY",
                    "raw": {"state": "DISABLED"},
                }
            ],
        }
        res = evaluate(None, resources)
        cw = res["cloudwatch_alarms"][0]
        self.assertEqual(cw["status"], "WARNING")
        self.assertEqual({i["rule_id"] for i in cw["issues"]}, {"CW-001", "CW-002"})
        ev = res["eventbridge_rules"][0]
        self.assertEqual(ev["status"], "ORPHANED")
        self.assertEqual(ev["issues"][0]["rule_id"], "EV-001")

    def test_cloudformation_lambda_elb_vpc(self):
        """Tests CFN-001/002, LAM-001, ELB-001, VPC-001."""
        old_date = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        resources = {
            "cloudformation_stacks": [
                {
                    "id": "failed-stack",
                    "name": "failed-stack",
                    "type": "cloudformation_stack",
                    "status": "HEALTHY",
                    "raw": {
                        "stack_status": "ROLLBACK_COMPLETE",
                        "enable_termination_protection": False,
                    },
                }
            ],
            "lambda_functions": [
                {
                    "id": "stale-fn",
                    "name": "stale-fn",
                    "type": "lambda_function",
                    "status": "HEALTHY",
                    "raw": {"last_modified": old_date},
                }
            ],
            "load_balancers": [
                {
                    "id": "public-alb",
                    "name": "public-alb",
                    "type": "load_balancer",
                    "status": "HEALTHY",
                    "raw": {"scheme": "internet-facing"},
                }
            ],
            "vpcs": [
                {
                    "id": "vpc-default",
                    "name": "vpc-default",
                    "type": "vpc",
                    "status": "HEALTHY",
                    "raw": {"is_default": True, "cidr_block": "172.31.0.0/16"},
                }
            ],
        }
        res = evaluate(None, resources)
        self.assertEqual(res["cloudformation_stacks"][0]["status"], "ORPHANED")
        self.assertEqual(res["lambda_functions"][0]["status"], "WARNING")
        self.assertEqual(res["lambda_functions"][0]["issues"][0]["rule_id"], "LAM-001")
        self.assertEqual(res["load_balancers"][0]["status"], "WARNING")
        self.assertEqual(res["load_balancers"][0]["issues"][0]["rule_id"], "ELB-001")
        self.assertEqual(res["vpcs"][0]["status"], "WARNING")
        self.assertEqual(res["vpcs"][0]["issues"][0]["rule_id"], "VPC-001")

    def test_status_severity_aggregation_hierarchy(self):
        """CRITICAL always takes priority over WARNING and ORPHANED; WARNING over ORPHANED."""
        # Resource with CRITICAL and WARNING
        resources = {
            "redshift_clusters": [
                {
                    "id": "mixed-cluster",
                    "name": "mixed-cluster",
                    "type": "redshift_cluster",
                    "status": "HEALTHY",
                    "raw": {
                        "publicly_accessible": True,   # RS-001 (CRITICAL)
                        "encrypted": False,             # RS-002 (WARNING)
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        self.assertEqual(res["redshift_clusters"][0]["status"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
