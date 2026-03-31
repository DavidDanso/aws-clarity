from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        paginator = ec2.get_paginator("describe_snapshots")
        pages = paginator.paginate(OwnerIds=["self"])
        for page in pages:
            for snap in page.get("Snapshots", []):
                snap_id = snap.get("SnapshotId")
                tags = snap.get("Tags", [])
                name = next((t["Value"] for t in tags if t["Key"] == "Name"), snap_id)
                resources.append({
                    "id": snap_id,
                    "name": name,
                    "type": "ebs_snapshot",
                    "status": "HEALTHY",
                    "issues": [],
                    "raw": {
                        "volume_id": snap.get("VolumeId"),
                        "start_time": snap.get("StartTime"),
                        "volume_size": snap.get("VolumeSize"),
                        "description": snap.get("Description"),
                        "tags": tags
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning Snapshots: {e}")
    return resources
