from botocore.exceptions import ClientError
import logging

def scan(session, region="us-east-1"):
    resources = []
    try:
        client = session.client("ecr", region_name=region)
        paginator = client.get_paginator("describe_repositories")
        pages = paginator.paginate()
        for page in pages:
            for repo in page.get("repositories", []):
                name = repo.get("repositoryName")
                arn = repo.get("repositoryArn")
                
                mutability = repo.get("imageTagMutability")
                scan_config = repo.get("imageScanningConfiguration", {})
                
                resources.append({
                    "id": name,
                    "name": name,
                    "type": "ecr_repository",
                    "status": "HEALTHY",
                    "issues": [],
                    "region": region,
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
