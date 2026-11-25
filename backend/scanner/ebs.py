from botocore.exceptions import ClientError
from exceptions import ScannerError
from utils import sanitize_metadata_text


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                vol_id = volume.get("VolumeId")
                # Data minimization: extract only Name tag for display; discard all other tag values.
                tags = volume.get("Tags", [])
                raw_name = next((t.get("Value") for t in tags if t.get("Key") == "Name"), None)
                name = sanitize_metadata_text(raw_name, max_length=128) if raw_name else vol_id
                attachments = [
                    {"InstanceId": a.get("InstanceId"), "State": a.get("State")}
                    for a in volume.get("Attachments", [])
                    if isinstance(a, dict)
                ]
                resources.append({
                    "id": vol_id,
                    "name": name,
                    "type": "ebs_volume",
                    "service": "EBS",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "size": volume.get("Size"),
                        "state": volume.get("State"),
                        "encrypted": volume.get("Encrypted"),
                        "volume_type": volume.get("VolumeType"),
                        "attachments": attachments,
                        "create_time": volume.get("CreateTime"),
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
