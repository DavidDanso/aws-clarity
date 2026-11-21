from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_internet_gateways")
        for page in paginator.paginate():
            for igw in page.get("InternetGateways", []):
                igw_id = igw.get("InternetGatewayId")
                tags = igw.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), igw_id)

                resources.append({
                    "id": igw_id,
                    "name": name,
                    "type": "internet_gateway",
                    "service": "VPC",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "attachments": igw.get("Attachments", []),
                        "tags": tags,
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
