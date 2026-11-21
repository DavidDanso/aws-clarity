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

from utils import (
    CachedSession,
    SCAN_BOTO_CONFIG,
    assume_role,
    generate_scan_token,
    validate_external_id,
    validate_role_arn,
    verify_scan_token,
)
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
    s3,
    rds,
    dynamodb_tables,
    lambda_functions,
    iam,
    cloudwatch,
    cloudtrail,
)
from scanner.misconfig import (
    SERVICE_COVERAGE_MATRIX,
    evaluate,
    get_rules_catalog,
)

# Default AWS regions enabled in standard accounts (fallback only if ec2:DescribeRegions is denied)
DEFAULT_ENABLED_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ap-northeast-2", "ap-northeast-3",
    "ca-central-1", "sa-east-1",
]

TABLE_NAME = os.environ.get("SCAN_TABLE_NAME", "aws-clarity-scans")
_AWS_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
_dynamodb = None
_lambda_client = None

MAX_ENCODED_RESULT_BYTES = 350_000


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


# Permission probes for all 10 supported AWS services
CORE_PERMISSIONS = {
    "EC2": {
        "service": "EC2",
        "action": "ec2:DescribeInstances, ec2:DescribeRegions",
        "capability": "Enabled-region discovery, EC2 instances, Elastic IPs, and Security Groups",
        "test": lambda session: session.client("ec2", region_name="us-east-1", config=SCAN_BOTO_CONFIG).describe_instances(MaxResults=5),
    },
    "VPC": {
        "service": "VPC",
        "action": "ec2:DescribeVpcs",
        "capability": "VPCs, Internet Gateways, and NAT Gateways",
        "test": lambda session: session.client("ec2", region_name="us-east-1", config=SCAN_BOTO_CONFIG).describe_vpcs(MaxResults=5),
    },
    "S3": {
        "service": "S3",
        "action": "s3:ListAllMyBuckets",
        "capability": "Global S3 bucket discovery, public exposure, and encryption checks",
        "test": lambda session: session.client("s3", config=SCAN_BOTO_CONFIG).list_buckets(),
    },
    "IAM": {
        "service": "IAM",
        "action": "iam:ListRoles, iam:ListUsers",
        "capability": "IAM roles, users, MFA, access keys, policies, and trust relationships",
        "test": lambda session: session.client("iam", config=SCAN_BOTO_CONFIG).list_roles(MaxItems=1),
    },
    "Lambda": {
        "service": "Lambda",
        "action": "lambda:ListFunctions",
        "capability": "Serverless functions, runtimes, and staleness checks",
        "test": lambda session: session.client("lambda", region_name="us-east-1", config=SCAN_BOTO_CONFIG).list_functions(MaxItems=1),
    },
    "RDS": {
        "service": "RDS",
        "action": "rds:DescribeDBInstances",
        "capability": "RDS databases, public exposure, encryption, deletion protection, and backups",
        "test": lambda session: session.client("rds", region_name="us-east-1", config=SCAN_BOTO_CONFIG).describe_db_instances(MaxRecords=20),
    },
    "DynamoDB": {
        "service": "DynamoDB",
        "action": "dynamodb:ListTables, dynamodb:DescribeTable",
        "capability": "DynamoDB tables, encryption, and empty provisioned capacity detection",
        "test": lambda session: session.client("dynamodb", region_name="us-east-1", config=SCAN_BOTO_CONFIG).list_tables(Limit=1),
    },
    "EBS": {
        "service": "EBS",
        "action": "ec2:DescribeVolumes, ec2:DescribeSnapshots",
        "capability": "EBS volume encryption, unattached volumes, and orphaned snapshots",
        "test": lambda session: session.client("ec2", region_name="us-east-1", config=SCAN_BOTO_CONFIG).describe_volumes(MaxResults=5),
    },
    "CloudWatch": {
        "service": "CloudWatch",
        "action": "cloudwatch:DescribeAlarms, logs:DescribeLogGroups",
        "capability": "CloudWatch alarms and Log Group retention policies",
        "test": lambda session: session.client("cloudwatch", region_name="us-east-1", config=SCAN_BOTO_CONFIG).describe_alarms(MaxRecords=1),
    },
    "CloudTrail": {
        "service": "CloudTrail",
        "action": "cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus",
        "capability": "CloudTrail audit logging, multi-region coverage, and log validation",
        "test": lambda session: session.client("cloudtrail", region_name="us-east-1", config=SCAN_BOTO_CONFIG).describe_trails(includeShadowTrails=False),
    },
}

SCANNER_METADATA = {
    "ec2_instances": {"service": "EC2", "label": "EC2 Instances", "permission": "ec2:DescribeInstances", "capability": "Virtual machines & IMDSv2"},
    "elastic_ips": {"service": "EC2", "label": "Elastic IPs", "permission": "ec2:DescribeAddresses", "capability": "Idle public IPv4 addresses"},
    "security_groups": {"service": "EC2", "label": "Security Groups", "permission": "ec2:DescribeSecurityGroups", "capability": "Firewall ingress exposure"},
    "vpcs": {"service": "VPC", "label": "VPCs", "permission": "ec2:DescribeVpcs", "capability": "Virtual private clouds"},
    "internet_gateways": {"service": "VPC", "label": "Internet Gateways", "permission": "ec2:DescribeInternetGateways", "capability": "VPC internet gateways"},
    "nat_gateways": {"service": "VPC", "label": "NAT Gateways", "permission": "ec2:DescribeNatGateways", "capability": "Outbound routing & ongoing spend risk"},
    "s3_buckets": {"service": "S3", "label": "S3 Buckets", "permission": "s3:ListAllMyBuckets, s3:GetBucketLocation, s3:ListBucket, s3:GetBucketPolicyStatus, s3:GetBucketAcl, s3:GetEncryptionConfiguration, s3:GetBucketPublicAccessBlock", "capability": "S3 buckets & public exposure"},
    "iam_roles": {"service": "IAM", "label": "IAM Roles", "permission": "iam:ListRoles, iam:ListRolePolicies, iam:GetRolePolicy, iam:ListAttachedRolePolicies", "capability": "IAM roles, policies & trust relationships"},
    "iam_users": {"service": "IAM", "label": "IAM Users", "permission": "iam:ListUsers, iam:ListMFADevices, iam:ListAccessKeys, iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:GetUserPolicy", "capability": "IAM users, MFA & access key age"},
    "lambda_functions": {"service": "Lambda", "label": "Lambda Functions", "permission": "lambda:ListFunctions", "capability": "Serverless functions & runtimes"},
    "rds_instances": {"service": "RDS", "label": "RDS Databases", "permission": "rds:DescribeDBInstances", "capability": "Relational databases"},
    "dynamodb_tables": {"service": "DynamoDB", "label": "DynamoDB Tables", "permission": "dynamodb:ListTables, dynamodb:DescribeTable", "capability": "NoSQL tables & provisioned capacity"},
    "ebs_volumes": {"service": "EBS", "label": "EBS Volumes", "permission": "ec2:DescribeVolumes", "capability": "Block storage encryption & idle volumes"},
    "snapshots": {"service": "EBS", "label": "EBS Snapshots", "permission": "ec2:DescribeSnapshots", "capability": "Orphaned volume backups"},
    "cloudwatch_alarms": {"service": "CloudWatch", "label": "CloudWatch Alarms", "permission": "cloudwatch:DescribeAlarms", "capability": "Alarm actions & INSUFFICIENT_DATA state"},
    "cloudwatch_log_groups": {"service": "CloudWatch", "label": "CloudWatch Log Groups", "permission": "logs:DescribeLogGroups", "capability": "Log group retention & storage growth"},
    "cloudtrail_trails": {"service": "CloudTrail", "label": "CloudTrail Trails", "permission": "cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus", "capability": "Audit trail logging & multi-region coverage"},
}

OUT_OF_SCOPE_DISCLOSURES = [
    {"service": "AWS Cost Explorer & Billing APIs", "reason": "Deliberately excluded to keep scanning free ($0.01/request in AWS). AWS Clarity detects idle and wasteful resources from free configuration metadata."},
    {"service": "Paid AWS Security Services (GuardDuty / Config / Security Hub)", "reason": "Excluded so scanning never relies on or triggers paid AWS services."},
    {"service": "Other AWS Services Beyond the 10 Supported v1 Services", "reason": "v1 intentionally focuses on EC2, VPC, S3, IAM, Lambda, RDS, DynamoDB, EBS, CloudWatch, and CloudTrail for complete, accurate inventory."},
    {"service": "Customer Data Contents", "reason": "AWS Clarity never reads S3 object contents, RDS/DynamoDB rows, Lambda source code, or CloudWatch log events."},
]


def discover_enabled_regions(session) -> tuple[list[str], dict]:
    """Discover all enabled AWS regions in the connected account via ec2:DescribeRegions."""
    try:
        ec2_client = session.client("ec2", region_name="us-east-1", config=SCAN_BOTO_CONFIG)
        response = ec2_client.describe_regions(
            AllRegions=False,
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}],
        )
        regions = sorted(
            r["RegionName"]
            for r in response.get("Regions", [])
            if r.get("RegionName")
        )
        if regions:
            return regions, {"mode": "auto_discovered", "status": "COMPLETE", "count": len(regions)}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "AccessDenied")
        return list(DEFAULT_ENABLED_REGIONS), {
            "mode": "fallback_default_regions",
            "status": "INCOMPLETE",
            "reason": f"ec2:DescribeRegions failed ({code}); fell back to {len(DEFAULT_ENABLED_REGIONS)} default AWS regions. Opt-in regions may not be included.",
            "required_permission": "ec2:DescribeRegions",
        }
    except Exception as e:
        return list(DEFAULT_ENABLED_REGIONS), {
            "mode": "fallback_default_regions",
            "status": "INCOMPLETE",
            "reason": f"Region discovery failed ({e}); fell back to default AWS regions.",
            "required_permission": "ec2:DescribeRegions",
        }
    return list(DEFAULT_ENABLED_REGIONS), {"mode": "fallback_default_regions", "status": "COMPLETE", "count": len(DEFAULT_ENABLED_REGIONS)}


def _deduplicate_resources(items: list[dict]) -> list[dict]:
    """Deduplicate collected resources using canonical AWS identifier (ARN or type+region+id)."""
    seen = set()
    unique = []
    for item in items:
        raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
        canonical = raw.get("arn") or f"{item.get('type')}::{item.get('region')}::{item.get('id')}"
        if canonical in seen:
            continue
        seen.add(canonical)
        unique.append(item)
    return unique


def _encode_result(payload: dict) -> str:
    raw_bytes = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(raw_bytes, compresslevel=6)
    encoded = base64.b64encode(compressed).decode("ascii")
    if len(encoded) > MAX_ENCODED_RESULT_BYTES:
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
    return encoded


def _decode_result(item: dict) -> dict:
    if "result_gz" in item and item["result_gz"]:
        raw_bytes = gzip.decompress(base64.b64decode(item["result_gz"]))
        return json.loads(raw_bytes.decode("utf-8"))
    return json.loads(item["result"])


def validate_permissions(session) -> dict:
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


def run_scan(role_arn: str, regions=None, external_id: str | None = None) -> dict:
    scan_started = time.monotonic()
    collection_deadline = scan_started + 85.0  # Leave generous margin inside 120s Lambda timeout

    validated_arn = validate_role_arn(role_arn)
    validated_ext_id = validate_external_id(external_id)
    raw_session = assume_role(validated_arn, external_id=validated_ext_id)
    session = CachedSession(raw_session)

    identity = session.client("sts", region_name="us-east-1").get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity.get("Arn", "")

    # Discover ALL enabled AWS regions unless caller explicitly passed a custom region list
    scan_all_regions = regions is None or regions == "all" or regions == ["all"]
    if scan_all_regions:
        target_regions, region_discovery = discover_enabled_regions(session)
    else:
        target_regions = list(dict.fromkeys(regions))
        region_discovery = {"mode": "user_selected", "status": "COMPLETE", "count": len(target_regions)}

    regional_scanners = {
        "ec2_instances": ec2.scan,
        "elastic_ips": elastic_ip.scan,
        "security_groups": security_group.scan,
        "vpcs": vpcs.scan,
        "internet_gateways": internet_gateways.scan,
        "nat_gateways": nat_gateways.scan,
        "lambda_functions": lambda_functions.scan,
        "rds_instances": rds.scan,
        "dynamodb_tables": dynamodb_tables.scan,
        "ebs_volumes": ebs.scan,
        "snapshots": snapshots.scan,
        "cloudwatch_alarms": cloudwatch.scan_alarms,
        "cloudwatch_log_groups": cloudwatch.scan_log_groups,
        "cloudtrail_trails": cloudtrail.scan,
    }

    resources = {key: [] for key in regional_scanners}
    resources["s3_buckets"] = []
    resources["iam_roles"] = []
    resources["iam_users"] = []

    scanner_statuses = []
    coverage_failures = []

    if region_discovery.get("status") == "INCOMPLETE":
        coverage_failures.append({
            "service": "EC2",
            "label": "Region Discovery",
            "region": "global",
            "reason": region_discovery.get("reason", "Could not list enabled regions"),
            "required_permission": "ec2:DescribeRegions",
        })

    # Pre-warm one client per regional service once so botocore service JSON models
    # are loaded on the main thread before fanning out across worker threads.
    for svc_name in ("ec2", "lambda", "rds", "dynamodb", "cloudwatch", "logs", "cloudtrail", "s3", "iam"):
        try:
            session.client(svc_name, region_name="us-east-1" if svc_name not in ("s3", "iam") else None)
        except Exception:
            pass

    # Submit ALL regional + global collectors together in one thread pool with a hard deadline
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=64)
    future_to_task = {}
    for region in target_regions:
        for key, fn in regional_scanners.items():
            future_to_task[executor.submit(fn, session, region)] = (key, region)

    future_to_task[executor.submit(iam.scan_roles, session)] = ("iam_roles", "global")
    future_to_task[executor.submit(iam.scan_users, session)] = ("iam_users", "global")
    future_to_task[
        executor.submit(s3.scan, session, None if scan_all_regions else target_regions)
    ] = ("s3_buckets", "global")

    try:
        remaining = max(1.0, collection_deadline - time.monotonic())
        done, not_done = concurrent.futures.wait(future_to_task.keys(), timeout=remaining)

        for future in done:
            key, region = future_to_task[future]
            meta = SCANNER_METADATA[key]
            try:
                result = future.result()
                resources[key].extend(result)
                assessment_errors = _collect_assessment_errors(result)
                if assessment_errors:
                    reason = "; ".join(f"{name}: {msg}" for name, msg in assessment_errors[:5])
                    scanner_statuses.append(_scanner_status_entry(key, region, "INCOMPLETE", len(result), reason))
                    coverage_failures.append({
                        "service": meta["service"],
                        "label": meta["label"],
                        "region": region,
                        "reason": reason,
                        "required_permission": meta["permission"],
                    })
                else:
                    scanner_statuses.append(_scanner_status_entry(key, region, "COMPLETED", len(result)))
            except ScannerError as e:
                resources[key].extend(e.resources)
                state = "INCOMPLETE" if e.resources else "FAILED"
                scanner_statuses.append(_scanner_status_entry(key, region, state, len(e.resources), str(e)))
                coverage_failures.append({
                    "service": meta["service"],
                    "label": meta["label"],
                    "region": region,
                    "reason": str(e),
                    "required_permission": meta["permission"],
                })
            except Exception as e:
                scanner_statuses.append(_scanner_status_entry(key, region, "FAILED", 0, str(e)))
                coverage_failures.append({
                    "service": meta["service"],
                    "label": meta["label"],
                    "region": region,
                    "reason": str(e),
                    "required_permission": meta["permission"],
                })

        for future in not_done:
            future.cancel()
            key, region = future_to_task[future]
            meta = SCANNER_METADATA[key]
            reason = "Collector exceeded scan time budget"
            scanner_statuses.append(_scanner_status_entry(key, region, "TIMED_OUT", 0, reason))
            coverage_failures.append({
                "service": meta["service"],
                "label": meta["label"],
                "region": region,
                "reason": reason,
                "required_permission": meta["permission"],
            })
    finally:
        # Don't block Lambda exit waiting for any hung socket thread past deadline
        executor.shutdown(wait=False, cancel_futures=True)

    # Derive permission_checks summary from actual collector outcomes (avoids 10 extra sequential API calls)
    permission_checks = {}
    for svc_name, spec in CORE_PERMISSIONS.items():
        svc_failures = [f for f in coverage_failures if f.get("service") == svc_name]
        permission_checks[svc_name] = {
            "service": svc_name,
            "status": "MISSING" if svc_failures else "PASSED",
            "required_permission": spec["action"],
            "capability": spec["capability"],
            **({"message": svc_failures[0]["reason"]} if svc_failures else {}),
        }

    # Deduplicate every resource group by canonical AWS identifier
    for key in list(resources.keys()):
        resources[key] = _deduplicate_resources(resources[key])

    # Run deterministic rule evaluation
    resources = evaluate(session, resources, account_id=account_id, scanner_statuses=scanner_statuses)

    all_resources = [
        r
        for group in resources.values()
        if isinstance(group, list)
        for r in group
    ]

    # Record per-resource check failures into coverage_failures (keeping coverage separate from security severity)
    for r in all_resources:
        for chk in (r.get("assessment") or {}).get("checks", []):
            if chk.get("status") == "CHECK_FAILED":
                coverage_failures.append({
                    "service": r.get("service", ""),
                    "label": f"{r.get('name')} ({chk.get('rule_id')})",
                    "region": r.get("region", "global"),
                    "reason": chk.get("reason", "Check could not complete"),
                    "required_permission": SCANNER_METADATA.get(
                        next((k for k, v in resources.items() if r in v), ""),
                        {},
                    ).get("permission", ""),
                })

    # Account-level CloudTrail advisory when CloudTrail collector succeeded and 0 trails exist
    ct_statuses = [s for s in scanner_statuses if s["key"] == "cloudtrail_trails"]
    ct_all_ok = bool(ct_statuses) and all(s["status"] == "COMPLETED" for s in ct_statuses)
    account_advisories = []
    if ct_all_ok and len(resources.get("cloudtrail_trails", [])) == 0:
        account_advisories.append({
            "rule_id": "CT-000",
            "severity": "CRITICAL",
            "category": "Security",
            "service": "CloudTrail",
            "title": "No CloudTrail trails configured in this AWS account",
            "why": "Without an active multi-region CloudTrail trail, API events older than 90 days are not archived to S3 and unauthorized changes are difficult to audit.",
            "fix": "Open CloudTrail → Trails → Create trail, enable 'Apply trail to all regions', and enable log file validation.",
            "verify": "Re-scan in AWS Clarity and confirm an active multi-region CloudTrail trail appears.",
        })

    is_incomplete = len(coverage_failures) > 0 or any(
        (r.get("assessment") or {}).get("status") == "INCOMPLETE"
        for r in all_resources
    )

    summary = {
        "total_resources": len(all_resources),
        "critical_issues": sum(1 for r in all_resources if r.get("status") == "CRITICAL"),
        "warnings": sum(1 for r in all_resources if r.get("status") == "WARNING"),
        "unused": sum(1 for r in all_resources if r.get("status") == "UNUSED"),
        "healthy": sum(1 for r in all_resources if r.get("status") == "HEALTHY"),
        "incomplete_resources": sum(1 for r in all_resources if r.get("status") == "INCOMPLETE"),
        "cost_risk_findings": sum(
            1
            for r in all_resources
            for issue in r.get("issues", [])
            if issue.get("category") in ("Cost Risk", "Unused") or issue.get("severity") == "UNUSED"
        ),
    }

    # Build per-service coverage rollup (10 services)
    service_summary = []
    for svc_entry in SERVICE_COVERAGE_MATRIX:
        svc_name = svc_entry["service"]
        keys = [rt["key"] for rt in svc_entry["resource_types"]]
        svc_statuses = [s for s in scanner_statuses if s["key"] in keys]
        svc_resources_count = sum(len(resources.get(k, [])) for k in keys)
        svc_failures = [f for f in coverage_failures if f.get("service") == svc_name]
        svc_state = "INCOMPLETE" if (svc_failures or any(s["status"] != "COMPLETED" for s in svc_statuses)) else "COMPLETE"
        service_summary.append({
            "service": svc_name,
            "scope": svc_entry["scope"],
            "status": svc_state,
            "resource_count": svc_resources_count,
            "failure_count": len(svc_failures),
            "resource_types": svc_entry["resource_types"],
        })

    coverage = {
        "status": "INCOMPLETE" if is_incomplete else "COMPLETE",
        "is_partial": is_incomplete,
        "region_discovery": region_discovery,
        "regions_scanned": target_regions,
        "services_supported": [s["service"] for s in SERVICE_COVERAGE_MATRIX],
        "services_scanned": sorted({s["service"] for s in scanner_statuses if s["status"] in ("COMPLETED", "INCOMPLETE")}),
        "service_matrix": SERVICE_COVERAGE_MATRIX,
        "service_summary": service_summary,
        "resources_inspected": len(all_resources),
        "findings_detected": sum(len(r.get("issues", [])) for r in all_resources),
        "failures": coverage_failures,
        "unsupported_services": OUT_OF_SCOPE_DISCLOSURES,
        "scanner_statuses": scanner_statuses,
        "rules_catalog": get_rules_catalog(),
    }

    return {
        "status": "INCOMPLETE" if is_incomplete else "COMPLETE",
        "account_id": account_id,
        "caller_arn": caller_arn,
        "region": "all-enabled-regions" if scan_all_regions else (target_regions[0] if len(target_regions) == 1 else "multi-region"),
        "regions": target_regions,
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "partial": is_incomplete,
        "summary": summary,
        "account_advisories": account_advisories,
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

    # Synchronous connection verification & permission pre-check
    if body.get("action") == "precheck" or body.get("is_precheck") is True:
        try:
            session = assume_role(role_arn, external_id=external_id)
            identity = session.client("sts", config=SCAN_BOTO_CONFIG).get_caller_identity()
            enabled_regions, region_discovery = discover_enabled_regions(session)
            permission_checks = validate_permissions(session)
            return _response(200, {
                "status": "success",
                "account_id": identity["Account"],
                "caller_arn": identity.get("Arn", ""),
                "enabled_regions": enabled_regions,
                "region_discovery": region_discovery,
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

    # Default to scanning ALL enabled AWS regions unless specific regions are requested
    raw_regions = body.get("regions", "all")
    if raw_regions is None or raw_regions == "all" or raw_regions == ["all"]:
        regions_payload = "all"
    elif isinstance(raw_regions, list) and len(raw_regions) > 0 and all(isinstance(r, str) and r.strip() for r in raw_regions):
        regions_payload = [r.strip() for r in raw_regions]
    else:
        return _response(400, {
            "status": "error",
            "error_code": "NO_REGIONS_SELECTED",
            "message": "Specify 'all' to scan all enabled AWS regions, or provide a valid list of region IDs.",
        })

    table = _get_table()
    scan_id = str(uuid.uuid4())
    scan_token, token_hash = generate_scan_token()

    # Store only scan metadata + token hash (never store role_arn or external_id in DynamoDB)
    table.put_item(Item={
        "scan_id": scan_id,
        "token_hash": token_hash,
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
                "regions": regions_payload,
            }),
        )
    except Exception as e:
        _mark_failed(table, scan_id, "INTERNAL_ERROR", f"Failed to start background scan: {e}")

    return _response(202, {
        "status": "PENDING",
        "scan_id": scan_id,
        "scan_token": scan_token,
    })


def handle_worker(event):
    scan_id = event["scan_id"]
    role_arn = event["role_arn"]
    external_id = event.get("external_id")
    regions = event.get("regions", "all")
    table = _get_table()
    table.update_item(
        Key={"scan_id": scan_id},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "RUNNING"},
    )

    try:
        result = run_scan(role_arn, regions, external_id=external_id)
        encoded = _encode_result(result)
        final_state = "INCOMPLETE" if result.get("partial") else "COMPLETE"
        table.update_item(
            Key={"scan_id": scan_id},
            UpdateExpression="SET #s = :s, #r = :r",
            ExpressionAttributeNames={"#s": "status", "#r": "result_gz"},
            ExpressionAttributeValues={":s": final_state, ":r": encoded},
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

    # Extract tenant isolation token (case-insensitive HTTP headers)
    headers = {str(k).lower(): v for k, v in (event.get("headers") or {}).items()}
    provided_token = headers.get("x-scan-token")

    table = _get_table()
    item = table.get_item(Key={"scan_id": scan_id}).get("Item")

    if not item:
        return _response(404, {"status": "error", "message": "Scan not found or expired"})

    # Enforce per-scan tenant isolation via constant-time token hash comparison
    expected_hash = item.get("token_hash")
    if expected_hash and not verify_scan_token(provided_token, expected_hash):
        return _response(403, {
            "status": "error",
            "error_code": "UNAUTHORIZED_SCAN_ACCESS",
            "message": "Invalid or missing scan access token.",
        })

    if item["status"] in ("COMPLETE", "INCOMPLETE"):
        decoded = _decode_result(item)
        return _response(200, {**decoded, "scan_state": item["status"]})
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
            "Access-Control-Allow-Headers": "Content-Type,X-Scan-Token",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Cache-Control": "no-store",
        },
        "body": json.dumps(payload, default=str),
    }
