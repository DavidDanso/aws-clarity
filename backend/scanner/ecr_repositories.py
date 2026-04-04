from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("ecr", region_name="us-east-1")
        paginator = client.get_paginator("describe_repositories")
        pages = paginator.paginate()
        for page in pages:
            for repo in page.get("repositories", []):
                name = repo.get("repositoryName")
                arn = repo.get("repositoryArn")
                
                mutability = repo.get("imageTagMutability")
                scan_config = repo.get("imageScanningConfiguration", {})
                
                status = "HEALTHY"
                issues = []
                
                if mutability == "MUTABLE":
                    status = "WARNING"
                    issues.append("Image tags are mutable and can be overwritten")
                
                if not scan_config.get("scanOnPush", False):
                    if status != "CRITICAL":
                        status = "WARNING"
                    issues.append("Automatic vulnerability scanning on push is disabled")
                    
                resources.append({
                    "id": name,
                    "name": name,
                    "type": "ecr_repository",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "repository_arn": arn,
                        "created_at": repo.get("createdAt"),
                        "image_tag_mutability": mutability,
                        "image_scanning_configuration": scan_config
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning ECR repositories: {e}")
    return resources
