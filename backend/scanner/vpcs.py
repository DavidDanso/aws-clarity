from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            for vpc in page.get("Vpcs", []):
                vpc_id = vpc.get("VpcId")
                tags = vpc.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), vpc_id)

                resources.append({
                    "id": vpc_id,
                    "name": name,
                    "type": "vpc",
                    "service": "VPC",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "cidr_block": vpc.get("CidrBlock"),
                        "is_default": vpc.get("IsDefault", False),
                        "state": vpc.get("State"),
                        "tags": tags,
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
