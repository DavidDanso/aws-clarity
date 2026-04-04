from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        paginator = ec2.get_paginator("describe_nat_gateways")
        pages = paginator.paginate()
        for page in pages:
            for nat in page.get("NatGateways", []):
                nat_id = nat.get("NatGatewayId")
                tags = nat.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), nat_id)
                
                state = nat.get("State")
                status = "HEALTHY"
                issues = []
                
                if state == "available":
                    status = "WARNING"
                    issues.append("NAT Gateways cost ~$0.045/hour plus data charges. Verify this is still needed.")
                elif state == "failed":
                    status = "WARNING"
                    issues.append("NAT Gateway is in a failed state")
                
                resources.append({
                    "id": nat_id,
                    "name": name,
                    "type": "nat_gateway",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "state": state,
                        "vpc_id": nat.get("VpcId"),
                        "subnet_id": nat.get("SubnetId"),
                        "create_time": nat.get("CreateTime"),
                        "tags": tags
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning NAT gateways: {e}")
    return resources
