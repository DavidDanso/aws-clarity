from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, region="us-east-1"):
    resources = []

    # ALB / NLB / GWLB (ELBv2)
    try:
        elbv2_client = session.client("elbv2", region_name=region)
        paginator = elbv2_client.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                lb_name = lb.get("LoadBalancerName")
                subnets = [
                    az.get("SubnetId")
                    for az in lb.get("AvailabilityZones", [])
                    if az.get("SubnetId")
                ]

                resources.append({
                    "id": lb_name,
                    "name": lb_name,
                    "type": "load_balancer",
                    "status": "NOT_ASSESSED",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "arn": lb.get("LoadBalancerArn"),
                        "dns_name": lb.get("DNSName"),
                        "type": lb.get("Type"),
                        "scheme": lb.get("Scheme"),
                        "state": (lb.get("State") or {}).get("Code"),
                        "vpc_id": lb.get("VpcId"),
                        "subnet_id": ", ".join(subnets) if subnets else None,
                        "subnet_ids": subnets,
                        "security_groups": lb.get("SecurityGroups", []),
                        "created_time": lb.get("CreatedTime"),
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e

    # Classic ELB (ELBv1)
    try:
        elb_client = session.client("elb", region_name=region)
        paginator = elb_client.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancerDescriptions", []):
                lb_name = lb.get("LoadBalancerName")
                subnets = lb.get("Subnets", [])

                resources.append({
                    "id": lb_name,
                    "name": lb_name,
                    "type": "load_balancer",
                    "status": "NOT_ASSESSED",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "dns_name": lb.get("DNSName"),
                        "type": "classic",
                        "scheme": lb.get("Scheme"),
                        "vpc_id": lb.get("VPCId"),
                        "subnet_id": ", ".join(subnets) if subnets else None,
                        "subnet_ids": subnets,
                        "security_groups": lb.get("SecurityGroups", []),
                        "created_time": lb.get("CreatedTime"),
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e

    return resources
