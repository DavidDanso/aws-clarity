import concurrent.futures
from botocore.exceptions import ClientError
from exceptions import ScannerError


def _inspect_bucket(session, s3, bucket, selected_regions):
    bucket_name = bucket.get("Name")
    creation_date = bucket.get("CreationDate")
    assessment_errors = {}

    # Determine true bucket region
    try:
        location_resp = s3.get_bucket_location(Bucket=bucket_name)
        raw_location = location_resp.get("LocationConstraint")
        if raw_location is None:
            bucket_region = "us-east-1"
        elif raw_location == "EU":
            bucket_region = "eu-west-1"
        else:
            bucket_region = raw_location
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "AWS error")
        raw_location = None
        bucket_region = "global"
        assessment_errors["bucket_location"] = f"Could not determine bucket region: {code}"

    if selected_regions is not None and bucket_region != "global" and bucket_region not in selected_regions:
        return None

    item = {
        "id": bucket_name,
        "name": bucket_name,
        "type": "s3_bucket",
        "service": "S3",
        "status": "INCOMPLETE",
        "issues": [],
        "region": bucket_region,
        "raw": {
            "arn": f"arn:aws:s3:::{bucket_name}",
            "name": bucket_name,
            "creation_date": creation_date,
            "location": raw_location,
        },
    }
    if assessment_errors:
        item["assessment_errors"] = assessment_errors
    return item


def scan(session, selected_regions=None):
    """Discover all S3 buckets in the account (globally) with pagination support.

    If `selected_regions` is None (default when scanning all enabled regions),
    every bucket in the account is returned with its actual AWS region.
    """
    resources = []
    buckets = []
    try:
        s3 = session.client("s3")
        kwargs = {}
        while True:
            response = s3.list_buckets(**kwargs)
            buckets.extend(response.get("Buckets", []))
            token = response.get("ContinuationToken")
            if not token:
                break
            kwargs["ContinuationToken"] = token
    except ClientError as e:
        raise ScannerError(str(e), resources) from e

    if not buckets:
        return resources

    workers = min(16, len(buckets))
    if workers == 1:
        item = _inspect_bucket(session, s3, buckets[0], selected_regions)
        return [item] if item is not None else []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda b: _inspect_bucket(session, s3, b, selected_regions), buckets))
    return [item for item in results if item is not None]
