from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        s3 = session.client("s3")
        response = s3.list_buckets()
        for bucket in response.get("Buckets", []):
            bucket_name = bucket.get("Name")
            
            # Filter us-east-1 only
            try:
                location_resp = s3.get_bucket_location(Bucket=bucket_name)
                location = location_resp.get("LocationConstraint")
            except ClientError as e:
                logging.warning(f"Could not get location for bucket {bucket_name}: {e}")
                continue

            # AWS returns None for us-east-1 location
            if location is not None:
                continue

            # Check if bucket is empty
            try:
                objs_resp = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                is_empty = objs_resp.get("KeyCount", 0) == 0
            except ClientError as e:
                is_empty = False
                logging.warning(f"Could not list objects for bucket {bucket_name}: {e}")

            raw_data = {
                "creation_date": bucket.get("CreationDate"),
                "is_empty": is_empty
            }

            try:
                pol_resp = s3.get_bucket_policy_status(Bucket=bucket_name)
                raw_data["is_public_policy"] = pol_resp.get("PolicyStatus", {}).get("IsPublic", False)
            except ClientError as e:
                raw_data["is_public_policy"] = False

            try:
                acl_resp = s3.get_bucket_acl(Bucket=bucket_name)
                raw_data["acl_grants"] = acl_resp.get("Grants", [])
            except ClientError:
                raw_data["acl_grants"] = []

            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
                raw_data["is_encrypted"] = True
            except ClientError:
                raw_data["is_encrypted"] = False

            try:
                pab_resp = s3.get_public_access_block(Bucket=bucket_name)
                raw_data["public_access_block"] = pab_resp.get("PublicAccessBlockConfiguration", {})
            except ClientError:
                raw_data["public_access_block"] = {}

            resources.append({
                "id": bucket_name,
                "name": bucket_name,
                "type": "s3_bucket",
                "status": "HEALTHY",
                "issues": [],
                "raw": raw_data
            })
    except ClientError as e:
        logging.warning(f"Error scanning S3 buckets: {e}")
    return resources
