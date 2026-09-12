from botocore.exceptions import ClientError
import logging
from datetime import datetime, timezone

def scan(session, region="us-east-1"):
    resources = []
    try:
        lambda_client = session.client("lambda", region_name=region)
        paginator = lambda_client.get_paginator("list_functions")
        pages = paginator.paginate()
        for page in pages:
            for fn in page.get("Functions", []):
                fn_name = fn.get("FunctionName")
                
                status = "HEALTHY"
                issues = []
                
                last_modified_str = fn.get("LastModified")
                if last_modified_str:
                    try:
                        # AWS Lambda returns LastModified as "2023-11-20T12:34:56.789+0000"
                        if "+" in last_modified_str:
                            time_part = last_modified_str.split("+")[0]
                            last_mod_dt = datetime.strptime(time_part, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
                        else:
                            last_mod_dt = datetime.strptime(last_modified_str, "%Y-%m-%dT%H:%M:%S.%f%z")
                            
                        age_days = (datetime.now(timezone.utc) - last_mod_dt).days
                        if age_days > 90:
                            status = "WARNING"
                            issues.append("Function has not been modified in over 90 days — verify it is still needed")
                    except Exception as e:
                        logging.warning(f"Error parsing LastModified '{last_modified_str}' for function {fn_name}: {e}")

                vpc_config = fn.get("VpcConfig") or {}
                vpc_id = vpc_config.get("VpcId")
                subnet_ids = vpc_config.get("SubnetIds", [])
                sec_groups = vpc_config.get("SecurityGroupIds", [])
                role_arn = fn.get("Role")

                resources.append({
                    "id": fn_name,
                    "name": fn_name,
                    "type": "lambda_function",
                    "status": status,
                    "issues": issues,
                    "region": region,
                    "raw": {
                        "function_arn": fn.get("FunctionArn"),
                        "runtime": fn.get("Runtime"),
                        "memory_size": fn.get("MemorySize"),
                        "timeout": fn.get("Timeout"),
                        "last_modified": fn.get("LastModified"),
                        "code_size": fn.get("CodeSize"),
                        "role": role_arn,
                        "vpc_id": vpc_id,
                        "subnet_id": ", ".join(subnet_ids) if subnet_ids else None,
                        "subnet_ids": subnet_ids,
                        "security_groups": sec_groups,
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning Lambda functions: {e}")
    return resources
