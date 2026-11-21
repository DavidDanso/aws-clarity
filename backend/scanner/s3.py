from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, selected_regions=None):
    if selected_regions is None:
        selected_regions = ["us-east-1"]
    resources = []
    try:
        s3 = session.client("s3")
        response = s3.list_buckets()
    except ClientError as e:
        raise ScannerError(str(e), resources) from e

    for bucket in response.get("Buckets", []):
        bucket_name = bucket.get("Name")
        creation_date = bucket.get("CreationDate")
        assessment_errors = {}

        try:
            location_resp = s3.get_bucket_location(Bucket=bucket_name)
            raw_location = location_resp.get("LocationConstraint")
            # AWS returns None for us-east-1 and "EU" for legacy eu-west-1 buckets
            if raw_location is None:
                bucket_region = "us-east-1"
            elif raw_location == "EU":
                bucket_region = "eu-west-1"
            else:
                bucket_region = raw_location
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "AWS error")
            # If we cannot determine bucket location, skip filtering only if we cannot match region;
            # disclose as assessment error and associate with the primary requested region so it stays visible.
            raw_location = None
            bucket_region = selected_regions[0]
            assessment_errors["S3-001"] = f"Could not determine bucket region: {code}"

        if bucket_region not in selected_regions:
            continue

        is_empty = None
        if "S3-001" not in assessment_errors:
            try:
                objs_resp = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                is_empty = objs_resp.get("KeyCount", 0) == 0
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "AWS error")
                assessment_errors["S3-001"] = f"Could not inspect bucket objects: {code}"

        item = {
            "id": bucket_name,
            "name": bucket_name,
            "type": "s3_bucket",
            "status": "NOT_ASSESSED",
            "issues": [],
            "region": bucket_region,
            "raw": {
                "name": bucket_name,
                "creation_date": creation_date,
                "is_empty": is_empty,
                "location": raw_location,
            },
        }
        if assessment_errors:
            item["assessment_errors"] = assessment_errors
        resources.append(item)

    return resources
