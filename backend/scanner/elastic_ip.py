from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        response = ec2.describe_addresses()
        for address in response.get("Addresses", []):
            alloc_id = address.get("AllocationId") or address.get("PublicIp")
            tags = address.get("Tags", [])
            name = next((t["Value"] for t in tags if t["Key"] == "Name"), address.get("PublicIp") or alloc_id)
            resources.append({
                "id": alloc_id,
                "name": name,
                "type": "elastic_ip",
                "service": "EC2",
                "status": "INCOMPLETE",
                "issues": [],
                "region": region,
                "raw": {
                    "public_ip": address.get("PublicIp"),
                    "association_id": address.get("AssociationId"),
                    "instance_id": address.get("InstanceId"),
                    "domain": address.get("Domain"),
                    "tags": tags,
                },
            })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
