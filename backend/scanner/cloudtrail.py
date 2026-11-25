from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, region="us-east-1"):
    resources = []
    try:
        ct = session.client("cloudtrail", region_name=region)
        # includeShadowTrails=False ensures multi-region trails are discovered
        # strictly once in their HomeRegion with zero cross-region duplication.
        response = ct.describe_trails(includeShadowTrails=False)
    except ClientError as e:
        raise ScannerError(str(e), resources) from e

    for trail in response.get("trailList", []):
        home_region = trail.get("HomeRegion") or region
        if home_region != region:
            continue

        trail_name = trail.get("Name")
        trail_arn = trail.get("TrailARN") or trail_name
        assessment_errors = {}

        is_logging = None
        has_delivery_error = False
        try:
            status_resp = ct.get_trail_status(Name=trail_arn)
            is_logging = status_resp.get("IsLogging")
            has_delivery_error = bool(status_resp.get("LatestDeliveryError"))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "AWS error")
            assessment_errors["CT-001"] = f"Could not inspect trail logging status: {code}"

        # Data minimization: keep has_kms_key & has_delivery_error booleans instead of
        # full KMS key ARNs or free-text delivery error messages.
        item = {
            "id": trail_arn,
            "name": trail_name,
            "type": "cloudtrail_trail",
            "service": "CloudTrail",
            "status": "INCOMPLETE",
            "issues": [],
            "region": home_region,
            "raw": {
                "arn": trail_arn,
                "home_region": home_region,
                "s3_bucket_name": trail.get("S3BucketName"),
                "is_multi_region_trail": trail.get("IsMultiRegionTrail"),
                "log_file_validation_enabled": trail.get("LogFileValidationEnabled"),
                "include_global_service_events": trail.get("IncludeGlobalServiceEvents"),
                "has_kms_key": bool(trail.get("KmsKeyId")),
                "is_organization_trail": trail.get("IsOrganizationTrail", False),
                "is_logging": is_logging,
                "has_delivery_error": has_delivery_error,
            },
        }
        if assessment_errors:
            item["assessment_errors"] = assessment_errors
        resources.append(item)

    return resources
