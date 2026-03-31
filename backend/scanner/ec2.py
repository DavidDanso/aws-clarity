from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        paginator = ec2.get_paginator("describe_instances")
        pages = paginator.paginate()
        for page in pages:
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId")
                    tags = instance.get("Tags", [])
                    name = next((t["Value"] for t in tags if t["Key"] == "Name"), instance_id)
                    resources.append({
                        "id": instance_id,
                        "name": name,
                        "type": "ec2_instance",
                        "status": "HEALTHY",
                        "issues": [],
                        "raw": {
                            "instance_type": instance.get("InstanceType"),
                            "state": instance.get("State", {}).get("Name"),
                            "launch_time": instance.get("LaunchTime"),
                            "vpc_id": instance.get("VpcId"),
                            "subnet_id": instance.get("SubnetId"),
                            "security_groups": [sg.get("GroupId") for sg in instance.get("SecurityGroups", [])],
                            "tags": tags
                        }
                    })
    except ClientError as e:
        logging.warning(f"Error scanning EC2 instances: {e}")
    return resources
