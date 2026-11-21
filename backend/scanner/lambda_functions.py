from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, region="us-east-1"):
    resources = []
    try:
        lambda_client = session.client("lambda", region_name=region)
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                fn_name = fn.get("FunctionName")
                vpc_config = fn.get("VpcConfig") or {}
                vpc_id = vpc_config.get("VpcId") or None
                subnet_ids = vpc_config.get("SubnetIds", [])
                sec_groups = vpc_config.get("SecurityGroupIds", [])

                resources.append({
                    "id": fn_name,
                    "name": fn_name,
                    "type": "lambda_function",
                    "status": "NOT_ASSESSED",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "function_arn": fn.get("FunctionArn"),
                        "runtime": fn.get("Runtime"),
                        "package_type": fn.get("PackageType", "Zip"),
                        "memory_size": fn.get("MemorySize"),
                        "timeout": fn.get("Timeout"),
                        "last_modified": fn.get("LastModified"),
                        "code_size": fn.get("CodeSize"),
                        "role": fn.get("Role"),
                        "vpc_id": vpc_id,
                        "subnet_id": ", ".join(subnet_ids) if subnet_ids else None,
                        "subnet_ids": subnet_ids,
                        "security_groups": sec_groups,
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
