from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    
    # elbv2 (ALB/NLB)
    try:
        elbv2_client = session.client("elbv2", region_name="us-east-1")
        paginator = elbv2_client.get_paginator("describe_load_balancers")
        pages = paginator.paginate()
        for page in pages:
            for lb in page.get("LoadBalancers", []):
                lb_name = lb.get("LoadBalancerName")
                scheme = lb.get("Scheme")
                
                status = "HEALTHY"
                issues = []
                if scheme == "internet-facing":
                    status = "WARNING"
                    issues.append("Load balancer is publicly accessible. Confirm this is intentional.")
                
                resources.append({
                    "id": lb_name,  # ARN is LoadBalancerArn, but requirement says id and name is LoadBalancerName
                    "name": lb_name,
                    "type": "load_balancer",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "dns_name": lb.get("DNSName"),
                        "type": lb.get("Type"),
                        "scheme": scheme,
                        "vpc_id": lb.get("VpcId"),
                        "created_time": lb.get("CreatedTime")
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning elbv2 Load Balancers: {e}")

    # elb (Classic ELB)
    try:
        elb_client = session.client("elb", region_name="us-east-1")
        paginator = elb_client.get_paginator("describe_load_balancers")
        pages = paginator.paginate()
        for page in pages:
            for lb in page.get("LoadBalancerDescriptions", []):
                lb_name = lb.get("LoadBalancerName")
                scheme = lb.get("Scheme")
                
                status = "HEALTHY"
                issues = []
                if scheme == "internet-facing":
                    status = "WARNING"
                    issues.append("Load balancer is publicly accessible. Confirm this is intentional.")
                
                resources.append({
                    "id": lb_name,
                    "name": lb_name,
                    "type": "load_balancer",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "dns_name": lb.get("DNSName"),
                        "type": "classic",
                        "scheme": scheme,
                        "vpc_id": lb.get("VPCId"),
                        "created_time": lb.get("CreatedTime")
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning classic Load Balancers: {e}")

    return resources
