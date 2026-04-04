from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("secretsmanager", region_name="us-east-1")
        paginator = client.get_paginator("list_secrets")
        pages = paginator.paginate()
        for page in pages:
            for secret in page.get("SecretList", []):
                name = secret.get("Name")
                arn = secret.get("ARN")
                
                rotation_enabled = secret.get("RotationEnabled", False)
                kms_key_id = secret.get("KmsKeyId")
                
                status = "HEALTHY"
                issues = []
                
                if not rotation_enabled:
                    status = "WARNING"
                    issues.append("Secret rotation is not enabled")
                if not kms_key_id:
                    status = "WARNING"
                    issues.append("Secret is not encrypted with a customer managed KMS key")
                    
                resources.append({
                    "id": name,
                    "name": name,
                    "type": "secret",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "arn": arn,
                        "last_changed_date": secret.get("LastChangedDate"),
                        "last_accessed_date": secret.get("LastAccessedDate"),
                        "kms_key_id": kms_key_id,
                        "rotation_enabled": rotation_enabled
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning Secrets Manager: {e}")
    return resources
