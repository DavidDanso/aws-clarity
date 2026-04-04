from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("autoscaling", region_name="us-east-1")
        paginator = client.get_paginator("describe_auto_scaling_groups")
        pages = paginator.paginate()
        for page in pages:
            for asg in page.get("AutoScalingGroups", []):
                name = asg.get("AutoScalingGroupName")
                min_size = asg.get("MinSize", 0)
                max_size = asg.get("MaxSize", 0)
                desired = asg.get("DesiredCapacity", 0)
                
                status = "HEALTHY"
                issues = []
                
                if desired == 0 and min_size == 0:
                    status = "ORPHANED"
                    issues.append("Auto Scaling Group has zero desired and minimum capacity")
                    
                resources.append({
                    "id": name,
                    "name": name,
                    "type": "auto_scaling_group",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "min_size": min_size,
                        "max_size": max_size,
                        "desired_capacity": desired,
                        "created_time": asg.get("CreatedTime"),
                        "health_check_type": asg.get("HealthCheckType")
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning Auto Scaling Groups: {e}")
    return resources
