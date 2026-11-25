from botocore.exceptions import ClientError
from exceptions import ScannerError
from utils import sanitize_metadata_text


def _minimize_ip_permissions(ip_permissions) -> list[dict]:
    """Keep only protocol, port range, CIDR blocks, and referenced SG IDs.

    Explicitly discards free-text rule descriptions (`IpRanges[].Description`,
    `Ipv6Ranges[].Description`, `UserIdGroupPairs[].Description`) and owner IDs.
    """
    minimized = []
    for perm in ip_permissions or []:
        if not isinstance(perm, dict):
            continue
        minimized.append({
            "IpProtocol": perm.get("IpProtocol"),
            "FromPort": perm.get("FromPort"),
            "ToPort": perm.get("ToPort"),
            "IpRanges": [
                {"CidrIp": r.get("CidrIp")}
                for r in perm.get("IpRanges", [])
                if isinstance(r, dict) and r.get("CidrIp")
            ],
            "Ipv6Ranges": [
                {"CidrIpv6": r.get("CidrIpv6")}
                for r in perm.get("Ipv6Ranges", [])
                if isinstance(r, dict) and r.get("CidrIpv6")
            ],
            "UserIdGroupPairs": [
                {"GroupId": p.get("GroupId")}
                for p in perm.get("UserIdGroupPairs", [])
                if isinstance(p, dict) and p.get("GroupId")
            ],
        })
    return minimized


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg.get("GroupId")
                tags = sg.get("Tags", [])
                raw_name = next((t.get("Value") for t in tags if t.get("Key") == "Name"), None)
                name = sanitize_metadata_text(raw_name, max_length=128) if raw_name else (sg.get("GroupName") or sg_id)
                # Data minimization: discard free-text Group Description, Tags, and rule Descriptions.
                resources.append({
                    "id": sg_id,
                    "name": name,
                    "type": "security_group",
                    "service": "EC2",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "group_name": sanitize_metadata_text(sg.get("GroupName"), max_length=128) or None,
                        "vpc_id": sg.get("VpcId"),
                        "ip_permissions": _minimize_ip_permissions(sg.get("IpPermissions", [])),
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
