import unittest
import datetime
import os
import sys

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
                        "image_scanning_configuration": {"scanOnPush": False},
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
        self.assertIn("Tag immutability", ecr001["fix"])
        self.assertEqual(ecr001["resource_type"], "ecr_repository")

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
                        "image_scanning_configuration": {"scanOnPush": True},
                    },
                }
            ]
        }
        res = evaluate(None, resources)
        repo = res["ecr_repositories"][0]
        self.assertEqual(repo["status"], "HEALTHY")
        self.assertEqual(len(repo["issues"]), 0)

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
        """DynamoDB table without KMS CMK triggers DDB-001."""
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
                    "raw": {"kms_master_key_id": None},
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
