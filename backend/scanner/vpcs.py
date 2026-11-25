from botocore.exceptions import ClientError
from exceptions import ScannerError
from utils import sanitize_metadata_text


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            for vpc in page.get("Vpcs", []):
                vpc_id = vpc.get("VpcId")
                # Data minimization: extract only Name tag for display; discard all other tag values.
                tags = vpc.get("Tags", [])
                raw_name = next((t.get("Value") for t in tags if t.get("Key") == "Name"), None)
                name = sanitize_metadata_text(raw_name, max_length=128) if raw_name else vpc_id

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
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
