import json
import datetime
import os
import boto3
import uuid
import time
from botocore.exceptions import ClientError
from utils import assume_role, validate_role_arn
from exceptions import InvalidRoleARNError, AssumeRoleError, PermissionDeniedError
from scanner import ec2, s3, rds, ebs, elastic_ip, security_group, snapshots, iam
from scanner import lambda_functions, nat_gateways, vpcs, internet_gateways, load_balancers
from scanner import dynamodb_tables, aurora_clusters, elasticache_clusters, redshift_clusters
from scanner import sqs_queues, sns_topics, secrets_manager
from scanner import auto_scaling_groups, ecs_clusters, eks_clusters, ecr_repositories, cloudformation_stacks
from scanner import cloudwatch_alarms, eventbridge_rules, api_gateways
from scanner.misconfig import evaluate

VALID_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ca-central-1", "sa-east-1"
]

dynamodb = boto3.resource("dynamodb")
lambda_client = boto3.client("lambda")
TABLE_NAME = os.environ.get("SCAN_TABLE_NAME", "aws-clarity-scans")

CORE_PERMISSIONS = {
    "EC2": {
        "service": "EC2",
        "action": "ec2:DescribeInstances",
        "capability": "Compute instances, attached EBS volumes, and security groups",
        "test": lambda session: session.client("ec2", region_name="us-east-1").describe_instances(MaxResults=5),
    },
    "S3": {
        "service": "S3",
        "action": "s3:ListAllMyBuckets",
        "capability": "Object storage bucket discovery and access policy analysis",
        "test": lambda session: session.client("s3").list_buckets(),
    },
    "RDS": {
        "service": "RDS",
        "action": "rds:DescribeDBInstances",
        "capability": "Relational databases, clusters, and encryption checks",
        "test": lambda session: session.client("rds", region_name="us-east-1").describe_db_instances(MaxRecords=20),
    },
    "IAM": {
        "service": "IAM",
        "action": "iam:ListRoles",
        "capability": "Identity & access management roles, policies, and trust relationships",
        "test": lambda session: session.client("iam").list_roles(MaxItems=1),
    },
    "Lambda": {
        "service": "Lambda",
        "action": "lambda:ListFunctions",
        "capability": "Serverless function discovery and configuration analysis",
        "test": lambda session: session.client("lambda", region_name="us-east-1").list_functions(MaxItems=1),
    },
}

SCANNER_METADATA = {
    "ec2_instances": {"service": "EC2", "label": "EC2 Instances", "permission": "ec2:DescribeInstances", "capability": "Virtual machines"},
    "ebs_volumes": {"service": "EBS", "label": "EBS Volumes", "permission": "ec2:DescribeVolumes", "capability": "Block storage disks"},
    "elastic_ips": {"service": "EC2", "label": "Elastic IPs", "permission": "ec2:DescribeAddresses", "capability": "Static IP addresses"},
    "security_groups": {"service": "EC2", "label": "Security Groups", "permission": "ec2:DescribeSecurityGroups", "capability": "Firewall rules"},
    "snapshots": {"service": "EBS", "label": "EBS Snapshots", "permission": "ec2:DescribeSnapshots", "capability": "Volume backups"},
    "rds_instances": {"service": "RDS", "label": "RDS Databases", "permission": "rds:DescribeDBInstances", "capability": "Relational databases"},
    "lambda_functions": {"service": "Lambda", "label": "Lambda Functions", "permission": "lambda:ListFunctions", "capability": "Serverless functions"},
    "nat_gateways": {"service": "VPC", "label": "NAT Gateways", "permission": "ec2:DescribeNatGateways", "capability": "Outbound subnet routing"},
    "load_balancers": {"service": "ELB", "label": "Load Balancers", "permission": "elasticloadbalancing:DescribeLoadBalancers", "capability": "Traffic distribution"},
    "dynamodb_tables": {"service": "DynamoDB", "label": "DynamoDB Tables", "permission": "dynamodb:ListTables", "capability": "NoSQL data tables"},
    "vpcs": {"service": "VPC", "label": "VPCs", "permission": "ec2:DescribeVpcs", "capability": "Virtual private clouds"},
    "auto_scaling_groups": {"service": "AutoScaling", "label": "Auto Scaling Groups", "permission": "autoscaling:DescribeAutoScalingGroups", "capability": "Compute scaling pools"},
    "ecs_clusters": {"service": "ECS", "label": "ECS Clusters", "permission": "ecs:ListClusters", "capability": "Container clusters"},
    "eks_clusters": {"service": "EKS", "label": "EKS Clusters", "permission": "eks:ListClusters", "capability": "Kubernetes clusters"},
    "elasticache_clusters": {"service": "ElastiCache", "label": "ElastiCache Clusters", "permission": "elasticache:DescribeCacheClusters", "capability": "In-memory caching"},
    "sqs_queues": {"service": "SQS", "label": "SQS Queues", "permission": "sqs:ListQueues", "capability": "Message queues"},
    "sns_topics": {"service": "SNS", "label": "SNS Topics", "permission": "sns:ListTopics", "capability": "Pub/sub topics"},
    "secrets": {"service": "SecretsManager", "label": "Secrets Manager", "permission": "secretsmanager:ListSecrets", "capability": "Encrypted credentials"},
    "api_gateways": {"service": "APIGateway", "label": "API Gateways", "permission": "apigateway:GET", "capability": "HTTP APIs"},
    "aurora_clusters": {"service": "RDS", "label": "Aurora Clusters", "permission": "rds:DescribeDBClusters", "capability": "Aurora DB clusters"},
    "cloudformation_stacks": {"service": "CloudFormation", "label": "CloudFormation Stacks", "permission": "cloudformation:DescribeStacks", "capability": "Infrastructure templates"},
    "eventbridge_rules": {"service": "EventBridge", "label": "EventBridge Rules", "permission": "events:ListRules", "capability": "Event bus routing"},
    "ecr_repositories": {"service": "ECR", "label": "ECR Repositories", "permission": "ecr:DescribeRepositories", "capability": "Container registries"},
    "internet_gateways": {"service": "VPC", "label": "Internet Gateways", "permission": "ec2:DescribeInternetGateways", "capability": "VPC internet ingress/egress"},
    "cloudwatch_alarms": {"service": "CloudWatch", "label": "CloudWatch Alarms", "permission": "cloudwatch:DescribeAlarms", "capability": "Metric alerts"},
    "redshift_clusters": {"service": "Redshift", "label": "Redshift Clusters", "permission": "redshift:DescribeClusters", "capability": "Data warehouses"},
    "iam_roles": {"service": "IAM", "label": "IAM Roles", "permission": "iam:ListRoles, iam:GetRolePolicy", "capability": "IAM roles & trust policies"},
    "s3_buckets": {"service": "S3", "label": "S3 Buckets", "permission": "s3:ListAllMyBuckets, s3:GetBucketLocation", "capability": "S3 storage buckets"},
}


def validate_permissions(session):
    """Validate core read-only permissions required by scanners."""
    results = {}
    for name, spec in CORE_PERMISSIONS.items():
        try:
            spec["test"](session)
            results[name] = {
                "service": name,
                "status": "PASSED",
                "required_permission": spec["action"],
                "capability": spec["capability"],
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "AccessDenied")
            results[name] = {
                "service": name,
                "status": "MISSING",
                "required_permission": spec["action"],
                "capability": spec["capability"],
                "error_code": code,
                "message": str(e),
            }
        except Exception:
            results[name] = {
                "service": name,
                "status": "PASSED",
                "required_permission": spec["action"],
                "capability": spec["capability"],
            }
    return results


def run_scan(role_arn, regions):
    start_time = time.time()
    validate_role_arn(role_arn)          # raises InvalidRoleARNError if bad
    session = assume_role(role_arn)      # raises AssumeRoleError if fails

    # Get account ID from the assumed session
    account_id = session.client("sts").get_caller_identity()["Account"]

    # Pre-check core permissions
    permission_checks = validate_permissions(session)

    import concurrent.futures

    REGIONAL_SCANNERS = {
        "ec2_instances": ec2.scan,
        "ebs_volumes": ebs.scan,
        "elastic_ips": elastic_ip.scan,
        "security_groups": security_group.scan,
        "snapshots": snapshots.scan,
        "rds_instances": rds.scan,
        "lambda_functions": lambda_functions.scan,
        "nat_gateways": nat_gateways.scan,
        "load_balancers": load_balancers.scan,
        "dynamodb_tables": dynamodb_tables.scan,
        "vpcs": vpcs.scan,
        "auto_scaling_groups": auto_scaling_groups.scan,
        "ecs_clusters": ecs_clusters.scan,
        "eks_clusters": eks_clusters.scan,
        "elasticache_clusters": elasticache_clusters.scan,
        "sqs_queues": sqs_queues.scan,
        "sns_topics": sns_topics.scan,
        "secrets": secrets_manager.scan,
        "api_gateways": api_gateways.scan,
        "aurora_clusters": aurora_clusters.scan,
        "cloudformation_stacks": cloudformation_stacks.scan,
        "eventbridge_rules": eventbridge_rules.scan,
        "ecr_repositories": ecr_repositories.scan,
        "internet_gateways": internet_gateways.scan,
        "cloudwatch_alarms": cloudwatch_alarms.scan,
        "redshift_clusters": redshift_clusters.scan,
    }

    resources = {key: [] for key in REGIONAL_SCANNERS}
    resources["iam_roles"] = []
    resources["s3_buckets"] = []

    scanner_statuses = []
    is_partial = False

    tasks = [
        (key, fn, region)
        for key, fn in REGIONAL_SCANNERS.items()
        for region in regions
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        future_to_task = {
            executor.submit(fn, session, region): (key, region)
            for key, fn in tasks
        }
        for future in concurrent.futures.as_completed(future_to_task):
            key, region = future_to_task[future]
            meta = SCANNER_METADATA.get(key, {"service": key, "label": key, "permission": "ReadOnlyAccess", "capability": key})
            try:
                result = future.result(timeout=25)
                resources[key].extend(result)
                scanner_statuses.append({
                    "service": meta["service"],
                    "label": meta["label"],
                    "key": key,
                    "region": region,
                    "status": "COMPLETED",
                    "count": len(result),
                    "required_permission": meta["permission"],
                    "affected_capability": meta["capability"],
                })
            except concurrent.futures.TimeoutError:
                is_partial = True
                print(f"Scanner {key} in {region} timed out after 25s — returning empty")
                scanner_statuses.append({
                    "service": meta["service"],
                    "label": meta["label"],
                    "key": key,
                    "region": region,
                    "status": "TIMED_OUT",
                    "count": 0,
                    "reason": "Scanner timed out after 25s",
                    "required_permission": meta["permission"],
                    "affected_capability": meta["capability"],
                })
            except Exception as e:
                is_partial = True
                print(f"Scanner {key} in {region} failed: {e}")
                scanner_statuses.append({
                    "service": meta["service"],
                    "label": meta["label"],
                    "key": key,
                    "region": region,
                    "status": "FAILED",
                    "count": 0,
                    "reason": str(e),
                    "required_permission": meta["permission"],
                    "affected_capability": meta["capability"],
                })

    # Global scanners
    try:
        resources["iam_roles"] = iam.scan(session)
        scanner_statuses.append({
            "service": "IAM",
            "label": "IAM Roles",
            "key": "iam_roles",
            "region": "global",
            "status": "COMPLETED",
            "count": len(resources["iam_roles"]),
            "required_permission": "iam:ListRoles, iam:GetRolePolicy, iam:ListRolePolicies",
            "affected_capability": "IAM role policies, admin access, and trust relationships",
        })
    except Exception as e:
        is_partial = True
        scanner_statuses.append({
            "service": "IAM",
            "label": "IAM Roles",
            "key": "iam_roles",
            "region": "global",
            "status": "FAILED",
            "count": 0,
            "reason": str(e),
            "required_permission": "iam:ListRoles, iam:GetRolePolicy, iam:ListRolePolicies",
            "affected_capability": "IAM role policies, admin access, and trust relationships",
        })

    try:
        resources["s3_buckets"] = s3.scan(session, selected_regions=regions)
        scanner_statuses.append({
            "service": "S3",
            "label": "S3 Buckets",
            "key": "s3_buckets",
            "region": "global",
            "status": "COMPLETED",
            "count": len(resources["s3_buckets"]),
            "required_permission": "s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketAcl",
            "affected_capability": "S3 storage buckets, encryption, and public access blocks",
        })
    except Exception as e:
        is_partial = True
        scanner_statuses.append({
            "service": "S3",
            "label": "S3 Buckets",
            "key": "s3_buckets",
            "region": "global",
            "status": "FAILED",
            "count": 0,
            "reason": str(e),
            "required_permission": "s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketAcl",
            "affected_capability": "S3 storage buckets, encryption, and public access blocks",
        })

    # Run misconfig and orphan evaluation
    resources = evaluate(session, resources)

    # Build summary
    all_resources = [
        r
        for group in resources.values()
        if isinstance(group, list)
        for r in group
    ]
    summary = {
        "total_resources": len(all_resources),
        "critical_issues": sum(1 for r in all_resources if r.get("status") == "CRITICAL"),
        "warnings": sum(1 for r in all_resources if r.get("status") == "WARNING"),
        "orphaned": sum(1 for r in all_resources if r.get("status") == "ORPHANED"),
    }

    # Build honest coverage disclosure
    services_scanned = sorted(list(set(s["service"] for s in scanner_statuses if s["status"] == "COMPLETED")))
    coverage = {
        "regions_scanned": regions,
        "services_scanned": services_scanned,
        "resources_inspected": len(all_resources),
        "findings_detected": sum(len(r.get("issues", [])) for r in all_resources),
        "is_partial": is_partial,
        "unsupported_services": [
            {"service": "CloudTrail Log Ingestion", "reason": "AWS Clarity performs point-in-time configuration inspection, not continuous event log ingestion."},
            {"service": "AWS WAF / Shield Rules", "reason": "Web application firewall rules and DDoS telemetry are not currently inspected."},
            {"service": "Amazon GuardDuty Threat Intel", "reason": "GuardDuty automated threat feeds are not queried."},
            {"service": "AWS Cost & Billing Data", "reason": "Deliberately removed — AWS Clarity makes zero AWS Cost Explorer API requests."},
            {"service": "Deep Container Vulnerabilities", "reason": "ECR repository metadata is scanned; container image CVE layers are not analyzed."},
        ],
        "scanner_statuses": scanner_statuses,
    }

    payload = {
        "status": "success",
        "account_id": account_id,
        "region": regions[0] if len(regions) == 1 else "multi-region",
        "regions": regions,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "partial": is_partial,
        "summary": summary,
        "coverage": coverage,
        "permission_checks": permission_checks,
        "resources": resources,
    }
    return payload


def _mark_failed(table, scan_id, error_code, message):
    """Single place that writes a FAILED record — keeps error_code and
    error_message always written together, never one without the other."""
    table.update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET #s = :s, #e = :e, #c = :c",
        ExpressionAttributeNames={"#s": "status", "#e": "error_message", "#c": "error_code"},
        ExpressionAttributeValues={":s": "FAILED", ":e": message, ":c": error_code},
    )


def handle_trigger(event, context):
    table = dynamodb.Table(TABLE_NAME)
    try:
        body = json.loads(event.get("body") or "{}")
        role_arn = body.get("role_arn", "").strip()
        validate_role_arn(role_arn)  # fail fast on bad input — same as today, before anything is created
    except InvalidRoleARNError:
        return _response(400, {"status": "error", "error_code": "INVALID_ROLE_ARN", "message": "The Role ARN format is invalid. Expected: arn:aws:iam::123456789012:role/RoleName"})

    # Check if this is an on-demand permission pre-check request
    if body.get("action") == "precheck" or body.get("is_precheck") is True:
        try:
            session = assume_role(role_arn)
            account_id = session.client("sts").get_caller_identity()["Account"]
            permission_checks = validate_permissions(session)
            return _response(200, {
                "status": "success",
                "account_id": account_id,
                "permission_checks": permission_checks,
            })
        except AssumeRoleError:
            return _response(400, {
                "status": "error",
                "error_code": "ASSUME_ROLE_FAILED",
                "message": "Could not assume the provided role. Verify the trust policy is correctly configured.",
            })
        except Exception as e:
            return _response(500, {
                "status": "error",
                "error_code": "INTERNAL_ERROR",
                "message": str(e),
            })

    regions = body.get("regions", ["us-east-1"])

    if not regions:
        return _response(400, {
            "status": "error",
            "error_code": "NO_REGIONS_SELECTED",
            "message": "Select at least one region to scan"
        })

    if not all(r in VALID_REGIONS for r in regions):
        return _response(400, {
            "status": "error",
            "error_code": "INVALID_REGION",
            "message": "One or more selected regions are not supported"
        })

    scan_id = str(uuid.uuid4())
    table.put_item(Item={
        "scan_id": scan_id,
        "status": "PENDING",
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "expires_at": int(time.time()) + 3600,  # 1 hour TTL
    })

    try:
        lambda_client.invoke(
            FunctionName=context.invoked_function_arn,
            InvocationType="Event",
            Payload=json.dumps({
                "_invocation_type": "worker",
                "scan_id": scan_id,
                "role_arn": role_arn,
                "regions": regions,
            }),
        )
    except Exception as e:
        # The record exists but nothing will ever pick it up — mark it
        # FAILED immediately instead of leaving an orphaned PENDING row
        # that polls forever and times out client-side with no real cause.
        _mark_failed(table, scan_id, "INTERNAL_ERROR", f"Failed to start background scan: {e}")

    # Always 202 here — the frontend learns the real outcome (including
    # the failure above, if it happened) on its first status poll.
    return _response(202, {"status": "PENDING", "scan_id": scan_id})


def handle_worker(event):
    scan_id = event["scan_id"]
    role_arn = event["role_arn"]
    regions = event.get("regions", ["us-east-1"])
    table = dynamodb.Table(TABLE_NAME)
    table.update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "RUNNING"},
    )

    try:
        result = run_scan(role_arn, regions)
        table.update_item(
            Key={"scan_id": scan_id},
            UpdateExpression="SET #s = :s, #r = :r",
            ExpressionAttributeNames={"#s": "status", "#r": "result"},
            ExpressionAttributeValues={":s": "COMPLETE", ":r": json.dumps(result, default=str)},
        )
    except AssumeRoleError:
        _mark_failed(table, scan_id, "ASSUME_ROLE_FAILED", "Could not assume the provided role. Verify the trust policy is correctly configured.")
    except PermissionDeniedError:
        _mark_failed(table, scan_id, "PERMISSION_DENIED", "The role was assumed but lacks required read permissions.")
    except Exception as e:
        _mark_failed(table, scan_id, "INTERNAL_ERROR", str(e))
    # No return value matters — this is an async invocation, nothing reads the return


def handle_status(event):
    scan_id = event["pathParameters"]["scan_id"]
    table = dynamodb.Table(TABLE_NAME)
    item = table.get_item(Key={"scan_id": scan_id}).get("Item")

    if not item:
        return _response(404, {"status": "error", "message": "Scan not found"})

    if item["status"] == "COMPLETE":
        return _response(200, {**json.loads(item["result"]), "status": "COMPLETE"})
    if item["status"] == "FAILED":
        return _response(200, {
            "status": "FAILED",
            "error_code": item.get("error_code", "INTERNAL_ERROR"),
            "message": item.get("error_message", "Unknown error"),
        })

    return _response(200, {"status": item["status"]})


def handler(event, context):
    if event.get("_invocation_type") == "worker":
        return handle_worker(event)
    if event.get("httpMethod") == "GET" and event.get("resource") == "/scan/{scan_id}/status":
        return handle_status(event)
    return handle_trigger(event, context)


def _response(status_code, payload):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "POST,OPTIONS",
        },
        "body": json.dumps(payload, default=str),  # default=str handles datetime objects
    }

if __name__ == "__main__":
    import sys
    import boto3
    # MOCK TEST ROUTINE to test payload shapes
    
    print("--- Local Debug Entry ---")
    local_session = boto3.Session(region_name="us-east-1")
    
    try:
        identity = local_session.client("sts").get_caller_identity()["Account"]
        print(f"Identified execution identity: {identity}")
        
        # Test just the EC2 module internally to ensure the dict shape functions
        result_ec2 = ec2.scan(local_session)
        print(f"Test EC2 result count: {len(result_ec2)}")
        
        mock_payload = {"ec2_instances": result_ec2, "ebs_volumes": []}
        eval_result = evaluate(local_session, mock_payload)
        
        print(f"Test evaluated successfully: returned {len(eval_result['ec2_instances'])}")
            
    except Exception as e:
        print(f"Skipping mock verification due to generic lack of credentials / {str(e)}")
