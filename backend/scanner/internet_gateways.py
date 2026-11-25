from botocore.exceptions import ClientError
from exceptions import ScannerError
from utils import sanitize_metadata_text


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_internet_gateways")
        for page in paginator.paginate():
            for igw in page.get("InternetGateways", []):
                igw_id = igw.get("InternetGatewayId")
                # Data minimization: extract only Name tag for display; discard all other tag values.
                tags = igw.get("Tags", [])
                raw_name = next((t.get("Value") for t in tags if t.get("Key") == "Name"), None)
                name = sanitize_metadata_text(raw_name, max_length=128) if raw_name else igw_id

                attachments = [
                    {"VpcId": a.get("VpcId"), "State": a.get("State")}
                    for a in igw.get("Attachments", [])
                    if isinstance(a, dict)
                ]

                resources.append({
                    "id": igw_id,
                    "name": name,
                    "type": "internet_gateway",
                    "service": "VPC",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "attachments": attachments,
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
