from botocore.exceptions import ClientError
import logging

def scan(session, selected_regions=None):
    if selected_regions is None:
        selected_regions = ["us-east-1"]
    try:
        resources = []
        s3 = session.client("s3")
        response = s3.list_buckets()
        
        for bucket in response.get("Buckets", []):
            bucket_name = bucket.get("Name")
            creation_date = bucket.get("CreationDate")
            
            try:
                location_resp = s3.get_bucket_location(Bucket=bucket_name)
                raw_location = location_resp["LocationConstraint"]
                bucket_region = raw_location if raw_location is not None else "us-east-1"
            except ClientError as e:
                logging.warning(f"Could not get location for bucket {bucket_name}: {e}")
                continue

            if bucket_region not in selected_regions:
                continue

            try:
                objs_resp = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                is_empty = objs_resp.get("KeyCount", 0) == 0
            except ClientError as e:
                is_empty = False
                logging.warning(f"Could not list objects for bucket {bucket_name}: {e}")

            resources.append({
                "id": bucket_name,
                "name": bucket_name,
                "type": "s3_bucket",
                "status": "HEALTHY",
                "issues": [],
                "region": bucket_region,
                "raw": {
                    "name": bucket_name,
                    "creation_date": creation_date,
                    "is_empty": is_empty,
                    "location": raw_location
                }
            })
            
        return resources

    except ClientError as e:
        logging.warning(f"Error scanning S3 buckets: {e}")
        return []
