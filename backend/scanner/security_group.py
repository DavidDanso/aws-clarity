from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg.get("GroupId")
                tags = sg.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), sg.get("GroupName") or sg_id)
                resources.append({
                    "id": sg_id,
                    "name": name,
                    "type": "security_group",
                    "service": "EC2",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "group_name": sg.get("GroupName"),
                        "description": sg.get("Description"),
                        "vpc_id": sg.get("VpcId"),
                        "ip_permissions": sg.get("IpPermissions", []),
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
