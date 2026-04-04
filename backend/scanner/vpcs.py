from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        paginator = ec2.get_paginator("describe_vpcs")
        pages = paginator.paginate()
        for page in pages:
            for vpc in page.get("Vpcs", []):
                vpc_id = vpc.get("VpcId")
                tags = vpc.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), vpc_id)
                
                is_default = vpc.get("IsDefault", False)
                status = "HEALTHY"
                issues = []
                
                if is_default:
                    status = "WARNING"
                    issues.append("This is the default VPC. Production resources should use a custom VPC.")
                
                resources.append({
                    "id": vpc_id,
                    "name": name,
                    "type": "vpc",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "cidr_block": vpc.get("CidrBlock"),
                        "is_default": is_default,
                        "state": vpc.get("State"),
                        "tags": tags
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning VPCs: {e}")
    return resources
