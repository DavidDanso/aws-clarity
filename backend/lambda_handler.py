import base64
import concurrent.futures
import datetime
import gzip
import json
import os
import time
import uuid
import boto3
from botocore.exceptions import ClientError

from utils import assume_role, validate_role_arn, validate_external_id
from exceptions import InvalidRoleARNError, AssumeRoleError, PermissionDeniedError, ScannerError
from scanner import (
    ec2,
    ebs,
    snapshots,
    elastic_ip,
    security_group,
    vpcs,
    internet_gateways,
    nat_gateways,
    load_balancers,
    s3,
    rds,
    dynamodb_tables,
    lambda_functions,
    iam,
)
from scanner.misconfig import evaluate, get_rules_catalog

VALID_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ca-central-1", "sa-east-1",
]

TABLE_NAME = os.environ.get("SCAN_TABLE_NAME", "aws-clarity-scans")
_AWS_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
_dynamodb = None
_lambda_client = None


def _get_table():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb", region_name=_AWS_REGION)
    return _dynamodb.Table(TABLE_NAME)


def _get_lambda_client():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda", region_name=_AWS_REGION)
    return _lambda_client

# DynamoDB item size ceiling is 400KB; compress scan payloads with gzip+base64
# so large accounts fit comfortably at zero additional AWS cost.
MAX_ENCODED_RESULT_BYTES = 350_000

CORE_PERMISSIONS = {
    "EC2": {
        "service": "EC2",
        "action": "ec2:DescribeInstances",
        "capability": "EC2 instances, EBS volumes, snapshots, Elastic IPs, VPCs, and Security Groups",
        "test": lambda session: session.client("ec2", region_name="us-east-1").describe_instances(MaxResults=5),
    },
    "S3": {
        "service": "S3",
        "action": "s3:ListAllMyBuckets",
        "capability": "S3 bucket discovery, public access, and encryption checks",
        "test": lambda session: session.client("s3").list_buckets(),
    },
    "RDS": {
        "service": "RDS",
        "action": "rds:DescribeDBInstances",
        "capability": "RDS relational databases, public access, encryption, and backups",
        "test": lambda session: session.client("rds", region_name="us-east-1").describe_db_instances(MaxRecords=20),
    },
    "DynamoDB": {
        "service": "DynamoDB",
        "action": "dynamodb:ListTables",
        "capability": "DynamoDB tables, encryption, and unused provisioned capacity",
        "test": lambda session: session.client("dynamodb", region_name="us-east-1").list_tables(Limit=1),
    },
    "Lambda": {
        "service": "Lambda",
        "action": "lambda:ListFunctions",
        "capability": "Lambda functions, deprecated runtimes, and stale function hygiene",
        "test": lambda session: session.client("lambda", region_name="us-east-1").list_functions(MaxItems=1),
    },
    "IAM": {
        "service": "IAM",
        "action": "iam:ListRoles",
        "capability": "IAM roles, wildcard policies, managed admin policies, and trust relationships",
        "test": lambda session: session.client("iam").list_roles(MaxItems=1),
    },
}

SCANNER_METADATA = {
    "ec2_instances": {"service": "EC2", "label": "EC2 Instances", "permission": "ec2:DescribeInstances", "capability": "Virtual machines & IMDSv2"},
    "ebs_volumes": {"service": "EC2", "label": "EBS Volumes", "permission": "ec2:DescribeVolumes", "capability": "Block storage disks & encryption"},
    "snapshots": {"service": "EC2", "label": "EBS Snapshots", "permission": "ec2:DescribeSnapshots", "capability": "Orphaned volume backups"},
    "elastic_ips": {"service": "EC2", "label": "Elastic IPs", "permission": "ec2:DescribeAddresses", "capability": "Idle public IPv4 addresses"},
    "security_groups": {"service": "EC2", "label": "Security Groups", "permission": "ec2:DescribeSecurityGroups", "capability": "Firewall ingress exposure"},
    "vpcs": {"service": "VPC", "label": "VPCs", "permission": "ec2:DescribeVpcs", "capability": "Virtual private clouds"},
    "internet_gateways": {"service": "VPC", "label": "Internet Gateways", "permission": "ec2:DescribeInternetGateways", "capability": "VPC internet gateways"},
    "nat_gateways": {"service": "VPC", "label": "NAT Gateways", "permission": "ec2:DescribeNatGateways", "capability": "Outbound routing & ongoing hourly cost risk"},
    "load_balancers": {"service": "ELB", "label": "Load Balancers", "permission": "elasticloadbalancing:DescribeLoadBalancers", "capability": "ALB, NLB & Classic load balancers"},
    "rds_instances": {"service": "RDS", "label": "RDS Databases", "permission": "rds:DescribeDBInstances", "capability": "Relational databases"},
    "dynamodb_tables": {"service": "DynamoDB", "label": "DynamoDB Tables", "permission": "dynamodb:ListTables, dynamodb:DescribeTable", "capability": "NoSQL tables & provisioned capacity"},
    "lambda_functions": {"service": "Lambda", "label": "Lambda Functions", "permission": "lambda:ListFunctions", "capability": "Serverless functions & runtimes"},
    "iam_roles": {"service": "IAM", "label": "IAM Roles", "permission": "iam:ListRoles, iam:ListRolePolicies, iam:GetRolePolicy, iam:ListAttachedRolePolicies", "capability": "IAM role policies & trust relationships"},
    "s3_buckets": {"service": "S3", "label": "S3 Buckets", "permission": "s3:ListAllMyBuckets, s3:GetBucketLocation, s3:ListBucket, s3:GetBucketPolicyStatus, s3:GetBucketAcl, s3:GetEncryptionConfiguration, s3:GetBucketPublicAccessBlock", "capability": "Object storage buckets & public exposure"},
}

UNSUPPORTED_SERVICES = [
    {"service": "AWS Cost Explorer & Billing APIs", "reason": "Deliberately excluded to keep scanning 100% free — Cost Explorer charges $0.01 per API request. AWS Clarity detects cost risks from free configuration metadata instead."},
    {"service": "CloudTrail & CloudWatch Logs", "reason": "AWS Clarity performs point-in-time configuration inspection, not continuous log ingestion."},
    {"service": "Amazon GuardDuty / Security Hub / AWS Config", "reason": "Paid security services are not queried to avoid incurring unexpected AWS API charges."},
    {"service": "EKS, ECS, Redshift, ElastiCache & Specialized Services", "reason": "Intentionally out of scope in v1 so the scanner remains focused, fast, and transparent across the most commonly used AWS services."},
    {"service": "Customer Data Contents", "reason": "AWS Clarity never reads S3 object contents, database records, or application payloads."},
]


def _encode_result(payload: dict) -> tuple[str, bool]:
    """Compress JSON payload with gzip+base64 for DynamoDB storage."""
    raw_bytes = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(raw_bytes, compresslevel=6)
    encoded = base64.b64encode(compressed).decode("ascii")
    if len(encoded) > MAX_ENCODED_RESULT_BYTES:
        # Trim bulky raw policy documents if an unusually large account still exceeds 350KB compressed
        trimmed = json.loads(raw_bytes.decode("utf-8"))
        for group in trimmed.get("resources", {}).values():
            if isinstance(group, list):
                for item in group:
                    raw = item.get("raw")
                    if isinstance(raw, dict):
                        raw.pop("inline_policies", None)
                        raw.pop("trust_policy", None)
                        raw.pop("ip_permissions", None)
        trimmed["truncated_raw_metadata"] = True
        compressed = gzip.compress(
            json.dumps(trimmed, default=str, separators=(",", ":")).encode("utf-8"),
            compresslevel=9,
        )
        encoded = base64.b64encode(compressed).decode("ascii")
    return encoded, True


def _decode_result(item: dict) -> dict:
    """Read either compressed (`result_gz`) or legacy uncompressed (`result`) scan payload."""
    if "result_gz" in item and item["result_gz"]:
        raw_bytes = gzip.decompress(base64.b64decode(item["result_gz"]))
        return json.loads(raw_bytes.decode("utf-8"))
    return json.loads(item["result"])


def validate_permissions(session) -> dict:
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
        except Exception as e:
            results[name] = {
                "service": name,
                "status": "MISSING",
                "required_permission": spec["action"],
                "capability": spec["capability"],
                "error_code": type(e).__name__,
                "message": str(e),
            }
    return results


def _scanner_status_entry(key: str, region: str, status: str, count: int, reason: str | None = None) -> dict:
    meta = SCANNER_METADATA.get(
        key,
        {"service": key, "label": key, "permission": "ReadOnlyAccess", "capability": key},
    )
    entry = {
        "service": meta["service"],
        "label": meta["label"],
        "key": key,
        "region": region,
        "status": status,
        "count": count,
        "required_permission": meta["permission"],
        "affected_capability": meta["capability"],
    }
    if reason:
        entry["reason"] = reason
    return entry


def _collect_assessment_errors(result: list[dict]) -> list[tuple[str, str]]:
    return [
        (item.get("name") or item.get("id") or "resource", message)
        for item in result
        for message in (item.get("assessment_errors") or {}).values()
    ]


def run_scan(role_arn: str, regions: list[str], external_id: str | None = None) -> dict:
    validated_arn = validate_role_arn(role_arn)
    validated_ext_id = validate_external_id(external_id)
    session = assume_role(validated_arn, external_id=validated_ext_id)

    account_id = session.client("sts").get_caller_identity()["Account"]
    permission_checks = validate_permissions(session)

    regional_scanners = {
        "ec2_instances": ec2.scan,
        "ebs_volumes": ebs.scan,
        "snapshots": snapshots.scan,
        "elastic_ips": elastic_ip.scan,
        "security_groups": security_group.scan,
        "vpcs": vpcs.scan,
        "internet_gateways": internet_gateways.scan,
        "nat_gateways": nat_gateways.scan,
        "load_balancers": load_balancers.scan,
        "rds_instances": rds.scan,
        "dynamodb_tables": dynamodb_tables.scan,
        "lambda_functions": lambda_functions.scan,
    }

    resources = {key: [] for key in regional_scanners}
    resources["iam_roles"] = []
    resources["s3_buckets"] = []

    scanner_statuses = []
    is_partial = False

    tasks = [
        (key, fn, region)
        for key, fn in regional_scanners.items()
        for region in regions
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        future_to_task = {
            executor.submit(fn, session, region): (key, region)
            for key, fn, region in tasks
        }
        for future in concurrent.futures.as_completed(future_to_task):
            key, region = future_to_task[future]
            try:
                result = future.result(timeout=25)
                resources[key].extend(result)
                assessment_errors = _collect_assessment_errors(result)
                if assessment_errors:
                    is_partial = True
                    reason = "; ".join(f"{name}: {msg}" for name, msg in assessment_errors[:5])
                    scanner_statuses.append(_scanner_status_entry(key, region, "PARTIAL", len(result), reason))
                else:
                    scanner_statuses.append(_scanner_status_entry(key, region, "COMPLETED", len(result)))
            except concurrent.futures.TimeoutError:
                is_partial = True
                scanner_statuses.append(_scanner_status_entry(key, region, "TIMED_OUT", 0, "Scanner timed out after 25s"))
            except ScannerError as e:
                is_partial = True
                resources[key].extend(e.resources)
                state = "PARTIAL" if e.resources else "FAILED"
                scanner_statuses.append(_scanner_status_entry(key, region, state, len(e.resources), str(e)))
            except Exception as e:
                is_partial = True
                scanner_statuses.append(_scanner_status_entry(key, region, "FAILED", 0, str(e)))

    # Global scanner: IAM Roles
    try:
        iam_result = iam.scan(session)
        resources["iam_roles"] = iam_result
        iam_errors = _collect_assessment_errors(iam_result)
        if iam_errors:
            is_partial = True
            reason = "; ".join(f"{name}: {msg}" for name, msg in iam_errors[:5])
            scanner_statuses.append(_scanner_status_entry("iam_roles", "global", "PARTIAL", len(iam_result), reason))
        else:
            scanner_statuses.append(_scanner_status_entry("iam_roles", "global", "COMPLETED", len(iam_result)))
    except ScannerError as e:
        is_partial = True
        resources["iam_roles"] = e.resources
        state = "PARTIAL" if e.resources else "FAILED"
        scanner_statuses.append(_scanner_status_entry("iam_roles", "global", state, len(e.resources), str(e)))
    except Exception as e:
        is_partial = True
        scanner_statuses.append(_scanner_status_entry("iam_roles", "global", "FAILED", 0, str(e)))

    # Global scanner: S3 Buckets (filtered to selected regions)
    try:
        s3_result = s3.scan(session, selected_regions=regions)
        resources["s3_buckets"] = s3_result
        s3_errors = _collect_assessment_errors(s3_result)
        if s3_errors:
            is_partial = True
            reason = "; ".join(f"{name}: {msg}" for name, msg in s3_errors[:5])
            scanner_statuses.append(_scanner_status_entry("s3_buckets", "global", "PARTIAL", len(s3_result), reason))
        else:
            scanner_statuses.append(_scanner_status_entry("s3_buckets", "global", "COMPLETED", len(s3_result)))
    except ScannerError as e:
        is_partial = True
        resources["s3_buckets"] = e.resources
        state = "PARTIAL" if e.resources else "FAILED"
        scanner_statuses.append(_scanner_status_entry("s3_buckets", "global", state, len(e.resources), str(e)))
    except Exception as e:
        is_partial = True
        scanner_statuses.append(_scanner_status_entry("s3_buckets", "global", "FAILED", 0, str(e)))

    # Deterministic misconfiguration & unused/cost-risk evaluation
    resources = evaluate(session, resources, account_id=account_id, scanner_statuses=scanner_statuses)

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
        "healthy": sum(1 for r in all_resources if r.get("status") == "HEALTHY"),
        "not_assessed": sum(1 for r in all_resources if r.get("status") == "NOT_ASSESSED"),
        "cost_risk_findings": sum(
            1
            for r in all_resources
            for issue in r.get("issues", [])
            if issue.get("category") in ("Cost Risk", "Unused")
        ),
    }

    is_partial = is_partial or any(
        r.get("assessment", {}).get("status") in ("PARTIAL", "NOT_ASSESSED")
        for r in all_resources
    )

    services_scanned = sorted({
        s["service"]
        for s in scanner_statuses
        if s["status"] in ("COMPLETED", "PARTIAL")
    })

    coverage = {
        "regions_scanned": regions,
        "services_scanned": services_scanned,
        "supported_resource_types": len(SCANNER_METADATA),
        "resources_inspected": len(all_resources),
        "findings_detected": sum(len(r.get("issues", [])) for r in all_resources),
        "is_partial": is_partial,
        "unsupported_services": UNSUPPORTED_SERVICES,
        "scanner_statuses": scanner_statuses,
        "rules_catalog": get_rules_catalog(),
    }

    return {
        "status": "success",
        "account_id": account_id,
        "region": regions[0] if len(regions) == 1 else "multi-region",
        "regions": regions,
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "partial": is_partial,
        "summary": summary,
        "coverage": coverage,
        "permission_checks": permission_checks,
        "resources": resources,
    }


def _mark_failed(table, scan_id: str, error_code: str, message: str):
    table.update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET #s = :s, #e = :e, #c = :c",
        ExpressionAttributeNames={"#s": "status", "#e": "error_message", "#c": "error_code"},
        ExpressionAttributeValues={":s": "FAILED", ":e": message, ":c": error_code},
    )


def handle_trigger(event, context):
    try:
        body = json.loads(event.get("body") or "{}")
        role_arn = validate_role_arn(body.get("role_arn", ""))
        external_id = validate_external_id(body.get("external_id"))
    except json.JSONDecodeError:
        return _response(400, {
            "status": "error",
            "error_code": "INVALID_REQUEST",
            "message": "Request body must be valid JSON.",
        })
    except InvalidRoleARNError as e:
        return _response(400, {
            "status": "error",
            "error_code": "INVALID_ROLE_ARN",
            "message": str(e),
        })

    # Synchronous permission pre-check
    if body.get("action") == "precheck" or body.get("is_precheck") is True:
        try:
            session = assume_role(role_arn, external_id=external_id)
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
                "message": "Could not assume the provided role. Verify the trust policy, App Account ID, and External ID.",
            })
        except Exception as e:
            return _response(500, {
                "status": "error",
                "error_code": "INTERNAL_ERROR",
                "message": str(e),
            })

    regions = body.get("regions", ["us-east-1"])
    if not isinstance(regions, list) or not regions:
        return _response(400, {
            "status": "error",
            "error_code": "NO_REGIONS_SELECTED",
            "message": "Select at least one region to scan.",
        })

    if not all(r in VALID_REGIONS for r in regions):
        return _response(400, {
            "status": "error",
            "error_code": "INVALID_REGION",
            "message": "One or more selected regions are not supported.",
        })

    table = _get_table()
    scan_id = str(uuid.uuid4())
    table.put_item(Item={
        "scan_id": scan_id,
        "status": "PENDING",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "expires_at": int(time.time()) + 3600,
    })

    try:
        _get_lambda_client().invoke(
            FunctionName=context.invoked_function_arn,
            InvocationType="Event",
            Payload=json.dumps({
                "_invocation_type": "worker",
                "scan_id": scan_id,
                "role_arn": role_arn,
                "external_id": external_id,
                "regions": regions,
            }),
        )
    except Exception as e:
        _mark_failed(table, scan_id, "INTERNAL_ERROR", f"Failed to start background scan: {e}")

    return _response(202, {"status": "PENDING", "scan_id": scan_id})


def handle_worker(event):
    scan_id = event["scan_id"]
    role_arn = event["role_arn"]
    external_id = event.get("external_id")
    regions = event.get("regions", ["us-east-1"])
    table = _get_table()
    table.update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "RUNNING"},
    )

    try:
        result = run_scan(role_arn, regions, external_id=external_id)
        encoded, _ = _encode_result(result)
        table.update_item(
            Key={"scan_id": scan_id},
            UpdateExpression="SET #s = :s, #r = :r",
            ExpressionAttributeNames={"#s": "status", "#r": "result_gz"},
            ExpressionAttributeValues={":s": "COMPLETE", ":r": encoded},
        )
    except AssumeRoleError:
        _mark_failed(
            table,
            scan_id,
            "ASSUME_ROLE_FAILED",
            "Could not assume the provided role. Verify the trust policy, App Account ID, and External ID.",
        )
    except PermissionDeniedError:
        _mark_failed(
            table,
            scan_id,
            "PERMISSION_DENIED",
            "The role was assumed but lacks required read permissions.",
        )
    except Exception as e:
        _mark_failed(table, scan_id, "INTERNAL_ERROR", str(e))


def handle_status(event):
    scan_id = (event.get("pathParameters") or {}).get("scan_id")
    if not scan_id:
        return _response(400, {"status": "error", "message": "Missing scan_id"})

    table = _get_table()
    item = table.get_item(Key={"scan_id": scan_id}).get("Item")

    if not item:
        return _response(404, {"status": "error", "message": "Scan not found or expired"})

    if item["status"] == "COMPLETE":
        return _response(200, {**_decode_result(item), "status": "COMPLETE"})
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


def _response(status_code: int, payload: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(payload, default=str),
    }
