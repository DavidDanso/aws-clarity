from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate():
            for nat in page.get("NatGateways", []):
                nat_id = nat.get("NatGatewayId")
                tags = nat.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), nat_id)

                eip_addrs = [
                    addr.get("PublicIp") or addr.get("AllocationId")
                    for addr in nat.get("NatGatewayAddresses", [])
                    if addr.get("PublicIp") or addr.get("AllocationId")
                ]

                resources.append({
                    "id": nat_id,
                    "name": name,
                    "type": "nat_gateway",
                    "service": "VPC",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "state": nat.get("State"),
                        "connectivity_type": nat.get("ConnectivityType"),
                        "vpc_id": nat.get("VpcId"),
                        "subnet_id": nat.get("SubnetId"),
                        "elastic_ip": ", ".join(eip_addrs) if eip_addrs else None,
                        "elastic_ips": eip_addrs,
                        "create_time": nat.get("CreateTime"),
                        "tags": tags,
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
