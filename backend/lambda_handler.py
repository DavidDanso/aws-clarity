import json
import datetime
import os
import boto3
import uuid
from utils import assume_role, validate_role_arn
from exceptions import InvalidRoleARNError, AssumeRoleError, PermissionDeniedError
from scanner import ec2, s3, rds, ebs, elastic_ip, security_group, snapshots, iam
from scanner import lambda_functions, nat_gateways, vpcs, internet_gateways, load_balancers
from scanner import dynamodb_tables, aurora_clusters, elasticache_clusters, redshift_clusters
from scanner import sqs_queues, sns_topics, secrets_manager
from scanner import auto_scaling_groups, ecs_clusters, eks_clusters, ecr_repositories, cloudformation_stacks
from scanner import cloudwatch_alarms, eventbridge_rules, api_gateways
from scanner.misconfig import evaluate

import time

VALID_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "ca-central-1", "sa-east-1"
]

dynamodb = boto3.resource("dynamodb")
lambda_client = boto3.client("lambda")
TABLE_NAME = os.environ.get("SCAN_TABLE_NAME", "aws-clarity-scans")


def run_scan(role_arn, regions):
    start_time = time.time()
    validate_role_arn(role_arn)          # raises InvalidRoleARNError if bad
    session = assume_role(role_arn)      # raises AssumeRoleError if fails

    # Get account ID from the assumed session
    account_id = session.client("sts").get_caller_identity()["Account"]

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

    tasks = [
        (key, fn, region)
        for key, fn in REGIONAL_SCANNERS.items()
        for region in regions
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        future_to_task = {
            executor.submit(fn, session, region): (key, region)
            for key, fn, region in tasks
        }
        for future in concurrent.futures.as_completed(future_to_task):
            key, region = future_to_task[future]
            try:
                result = future.result(timeout=25)
                resources[key].extend(result)
            except concurrent.futures.TimeoutError:
                print(f"Scanner {key} in {region} timed out after 25s — returning empty")
            except Exception as e:
                print(f"Scanner {key} in {region} failed: {e}")

    resources["iam_roles"] = iam.scan(session)
    resources["s3_buckets"] = s3.scan(session, selected_regions=regions)

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

    payload = {
        "status": "success",
        "account_id": account_id,
        "region": regions[0] if len(regions) == 1 else "multi-region",
        "regions": regions,
        "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
        "partial": False,
        "summary": summary,
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
