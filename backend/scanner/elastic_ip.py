from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.describe_addresses()
        for address in response.get("Addresses", []):
            alloc_id = address.get("AllocationId", address.get("PublicIp"))
            tags = address.get("Tags", [])
            name = next((t["Value"] for t in tags if t["Key"] == "Name"), address.get("PublicIp"))
            resources.append({
                "id": alloc_id,
                "name": name,
                "type": "elastic_ip",
                "status": "HEALTHY",
                "issues": [],
                "raw": {
                    "public_ip": address.get("PublicIp"),
                    "association_id": address.get("AssociationId"),
                    "instance_id": address.get("InstanceId"),
                    "domain": address.get("Domain"),
                    "tags": tags
                }
            })
    except ClientError as e:
        logging.warning(f"Error scanning Elastic IPs: {e}")
    return resources
