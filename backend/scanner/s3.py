from botocore.exceptions import ClientError
import logging

def scan(session):
    try:
        resources = []
        s3 = session.client("s3")
        response = s3.list_buckets()
        
        for bucket in response.get("Buckets", []):
            bucket_name = bucket.get("Name")
            creation_date = bucket.get("CreationDate")
            
            try:
                location_resp = s3.get_bucket_location(Bucket=bucket_name)
                location = location_resp.get("LocationConstraint")
            except ClientError as e:
                logging.warning(f"Could not get location for bucket {bucket_name}: {e}")
                continue

            if location is not None:
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
                "raw": {
                    "name": bucket_name,
                    "creation_date": creation_date,
                    "is_empty": is_empty,
                    "location": location
                }
            })
            
        return resources

    except ClientError as e:
        logging.warning(f"Error scanning S3 buckets: {e}")
        return []
