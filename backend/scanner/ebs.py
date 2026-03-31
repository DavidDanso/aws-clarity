from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        paginator = ec2.get_paginator("describe_volumes")
        pages = paginator.paginate()
        for page in pages:
            for volume in page.get("Volumes", []):
                vol_id = volume.get("VolumeId")
                tags = volume.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), vol_id)
                resources.append({
                    "id": vol_id,
                    "name": name,
                    "type": "ebs_volume",
                    "status": "HEALTHY",
                    "issues": [],
                    "raw": {
                        "size": volume.get("Size"),
                        "state": volume.get("State"),
                        "encrypted": volume.get("Encrypted"),
                        "volume_type": volume.get("VolumeType"),
                        "attachments": volume.get("Attachments", []),
                        "tags": tags,
                        "create_time": volume.get("CreateTime")
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning EBS volumes: {e}")
    return resources
