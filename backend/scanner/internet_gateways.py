from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        paginator = ec2.get_paginator("describe_internet_gateways")
        pages = paginator.paginate()
        for page in pages:
            for igw in page.get("InternetGateways", []):
                igw_id = igw.get("InternetGatewayId")
                tags = igw.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), igw_id)
                
                attachments = igw.get("Attachments", [])
                status = "HEALTHY"
                issues = []
                
                if len(attachments) == 0:
                    status = "ORPHANED"
                    issues.append("Internet Gateway is not attached to any VPC")
                
                resources.append({
                    "id": igw_id,
                    "name": name,
                    "type": "internet_gateway",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "attachments": attachments,
                        "tags": tags
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning Internet Gateways: {e}")
    return resources
