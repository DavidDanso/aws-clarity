from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        paginator = ec2.get_paginator("describe_security_groups")
        pages = paginator.paginate()
        for page in pages:
            for sg in page.get("SecurityGroups", []):
                sg_id = sg.get("GroupId")
                tags = sg.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), sg.get("GroupName"))
                
                resources.append({
                    "id": sg_id,
                    "name": name,
                    "type": "security_group",
                    "status": "HEALTHY",
                    "issues": [],
                    "raw": {
                        "group_name": sg.get("GroupName"),
                        "description": sg.get("Description"),
                        "vpc_id": sg.get("VpcId"),
                        "ip_permissions": sg.get("IpPermissions", [])
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning Security Groups: {e}")
    return resources
