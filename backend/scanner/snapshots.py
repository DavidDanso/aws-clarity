from botocore.exceptions import ClientError
from exceptions import ScannerError
from utils import sanitize_metadata_text


def scan(session, region="us-east-1"):
    resources = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                snap_id = snap.get("SnapshotId")
                # Data minimization: discard free-text Description and all non-Name tags.
                tags = snap.get("Tags", [])
                raw_name = next((t.get("Value") for t in tags if t.get("Key") == "Name"), None)
                name = sanitize_metadata_text(raw_name, max_length=128) if raw_name else snap_id
                resources.append({
                    "id": snap_id,
                    "name": name,
                    "type": "ebs_snapshot",
                    "service": "EBS",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "volume_id": snap.get("VolumeId"),
                        "start_time": snap.get("StartTime"),
                        "volume_size": snap.get("VolumeSize"),
                        "encrypted": snap.get("Encrypted"),
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
