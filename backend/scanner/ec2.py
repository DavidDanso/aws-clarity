from botocore.exceptions import ClientError
from exceptions import ScannerError
from utils import sanitize_metadata_text


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId")
                    # Data minimization: extract only the Name tag for display; discard all other tag values.
                    tags = instance.get("Tags", [])
                    raw_name = next((t.get("Value") for t in tags if t.get("Key") == "Name"), None)
                    name = sanitize_metadata_text(raw_name, max_length=128) if raw_name else instance_id

                    ebs_volumes = [
                        b["Ebs"]["VolumeId"]
                        for b in instance.get("BlockDeviceMappings", [])
                        if b.get("Ebs") and b["Ebs"].get("VolumeId")
                    ]

                    iam_profile = instance.get("IamInstanceProfile", {})
                    iam_role_arn = iam_profile.get("Arn") or iam_profile.get("Id")
                    metadata_options = instance.get("MetadataOptions") or {}
                    public_ip = instance.get("PublicIpAddress")

                    resources.append({
                        "id": instance_id,
                        "name": name,
                        "type": "ec2_instance",
                        "service": "EC2",
                        "status": "INCOMPLETE",
                        "issues": [],
                        "region": region,
                        "raw": {
                            "instance_type": instance.get("InstanceType"),
                            "state": (instance.get("State") or {}).get("Name"),
                            "launch_time": instance.get("LaunchTime"),
                            "vpc_id": instance.get("VpcId"),
                            "subnet_id": instance.get("SubnetId"),
                            "security_groups": [
                                sg.get("GroupId")
                                for sg in instance.get("SecurityGroups", [])
                                if sg.get("GroupId")
                            ],
                            "ebs_volumes": ebs_volumes,
                            "iam_instance_profile": iam_role_arn,
                            "http_tokens": metadata_options.get("HttpTokens"),
                            "has_public_ip": bool(public_ip),
                            "public_ip": public_ip,
                        },
                    })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
