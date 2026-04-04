import json
import datetime
from utils import assume_role, validate_role_arn
from exceptions import InvalidRoleARNError, AssumeRoleError, PermissionDeniedError
from scanner import ec2, s3, rds, ebs, elastic_ip, security_group, snapshots, iam
from scanner import lambda_functions, nat_gateways, vpcs, internet_gateways, load_balancers
from scanner import dynamodb_tables, aurora_clusters, elasticache_clusters, redshift_clusters
from scanner import sqs_queues, sns_topics, secrets_manager
from scanner.misconfig import evaluate

import time

def handler(event, context):
    try:
        start_time = time.time()
        body = json.loads(event.get("body") or "{}")
        role_arn = body.get("role_arn", "").strip()

        validate_role_arn(role_arn)          # raises InvalidRoleARNError if bad
        session = assume_role(role_arn)      # raises AssumeRoleError if fails

        # Get account ID from the assumed session
        account_id = session.client("sts").get_caller_identity()["Account"]

        import concurrent.futures

        # Run scanners with timeout protection
        resources = {}
        partial_scan = False
        
        scanner_map = {
            "ec2_instances": ec2.scan,
            "s3_buckets": s3.scan,
            "rds_instances": rds.scan,
            "ebs_volumes": ebs.scan,
            "elastic_ips": elastic_ip.scan,
            "security_groups": security_group.scan,
            "snapshots": snapshots.scan,
            "iam_roles": iam.scan,
            "lambda_functions": lambda_functions.scan,
            "nat_gateways": nat_gateways.scan,
            "vpcs": vpcs.scan,
            "internet_gateways": internet_gateways.scan,
            "load_balancers": load_balancers.scan,
            "dynamodb_tables": dynamodb_tables.scan,
            "aurora_clusters": aurora_clusters.scan,
            "elasticache_clusters": elasticache_clusters.scan,
            "redshift_clusters": redshift_clusters.scan,
            "sqs_queues": sqs_queues.scan,
            "sns_topics": sns_topics.scan,
            "secrets": secrets_manager.scan,
        }

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_key = {executor.submit(fn, session): key for key, fn in scanner_map.items()}
            for future in concurrent.futures.as_completed(future_to_key):
                key = future_to_key[future]
                if time.time() - start_time > 115:
                    partial_scan = True
                    break
                try:
                    resources[key] = future.result()
                except Exception as e:
                    print(f"Scanner {key} failed: {e}")
                    resources[key] = []
                    
        # Fill skipped scanners with empty lists to maintain schema
        for key in scanner_map.keys():
            if key not in resources:
                resources[key] = []

        # Run misconfig and orphan evaluation 
        resources = evaluate(session, resources)

        # Build summary
        all_resources = [r for group in resources.values() for r in group]
        summary = {
            "total_resources": len(all_resources),
            "critical_issues": sum(1 for r in all_resources if r.get("status") == "CRITICAL"),
            "warnings": sum(1 for r in all_resources if r.get("status") == "WARNING"),
            "orphaned": sum(1 for r in all_resources if r.get("status") == "ORPHANED"),
        }

        payload = {
            "status": "success",
            "account_id": account_id,
            "region": "us-east-1",
            "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
            "partial": partial_scan,
            "summary": summary,
            "resources": resources,
        }
        return _response(200, payload)

    except InvalidRoleARNError:
        return _response(400, {"status": "error", "error_code": "INVALID_ROLE_ARN", "message": "The Role ARN format is invalid. Expected: arn:aws:iam::123456789012:role/RoleName"})
    except AssumeRoleError:
        return _response(403, {"status": "error", "error_code": "ASSUME_ROLE_FAILED", "message": "Could not assume the provided role. Verify the trust policy is correctly configured."})
    except PermissionDeniedError:
        return _response(403, {"status": "error", "error_code": "PERMISSION_DENIED", "message": "The role was assumed but lacks required read permissions."})
    except Exception as e:
        return _response(500, {"status": "error", "error_code": "INTERNAL_ERROR", "message": str(e)})


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
