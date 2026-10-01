from botocore.exceptions import ClientError
import logging

def scan(session, region="us-east-1"):
    resources = []
    client = session.client("ecr", region_name=region)
    paginator = client.get_paginator("describe_repositories")
    repositories = [repo for page in paginator.paginate() for repo in page.get("repositories", [])]

    # BatchGetRepositoryScanningConfiguration returns the effective repository
    # scan frequency, including registry scanning rules and repository filters.
    # Its API accepts up to 25 repository names per request.
    scan_configs = {}
    scan_failures = {}
    scan_api_error = None
    names = [repo.get("repositoryName") for repo in repositories if repo.get("repositoryName")]
    for offset in range(0, len(names), 25):
        try:
            response = client.batch_get_repository_scanning_configuration(
                repositoryNames=names[offset:offset + 25]
            )
        except ClientError as e:
            scan_api_error = e.response.get("Error", {}).get("Code", "AWS error")
            break
        for config in response.get("scanningConfigurations", []):
            scan_configs[config.get("repositoryName")] = config
        for failure in response.get("failures", []):
            scan_failures[failure.get("repositoryName")] = failure.get("failureReason", "AWS did not return a scanning configuration")

    for repo in repositories:
        name = repo.get("repositoryName")
        arn = repo.get("repositoryArn")
        config = scan_configs.get(name, {})
        raw = {
            "repository_arn": arn,
            "created_at": repo.get("createdAt"),
            "image_tag_mutability": repo.get("imageTagMutability"),
            "image_tag_mutability_exclusion_filters": repo.get("imageTagMutabilityExclusionFilters"),
            "image_scanning_configuration": repo.get("imageScanningConfiguration"),
            "scan_frequency": config.get("scanFrequency"),
            "applied_scan_filters": config.get("appliedScanFilters"),
        }
        assessment_errors = {}
        if scan_api_error:
            assessment_errors["ECR-002"] = "Could not read effective repository scanning configuration: " + scan_api_error
        elif name in scan_failures:
            assessment_errors["ECR-002"] = scan_failures[name]
        elif not config:
            assessment_errors["ECR-002"] = "AWS returned no effective repository scanning configuration"

        resources.append({
            "id": name,
            "name": name,
            "type": "ecr_repository",
            "status": "NOT_ASSESSED",
            "issues": [],
            "region": region,
            "raw": raw,
            "assessment_errors": assessment_errors,
        })
    return resources
