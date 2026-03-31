from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        rds = session.client("rds", region_name="us-east-1")
        paginator = rds.get_paginator("describe_db_instances")
        pages = paginator.paginate()
        for page in pages:
            for db in page.get("DBInstances", []):
                db_id = db.get("DBInstanceIdentifier")
                name = db_id 
                resources.append({
                    "id": db_id,
                    "name": name,
                    "type": "rds_instance",
                    "status": "HEALTHY",
                    "issues": [],
                    "raw": {
                        "db_instance_class": db.get("DBInstanceClass"),
                        "engine": db.get("Engine"),
                        "status": db.get("DBInstanceStatus"),
                        "publicly_accessible": db.get("PubliclyAccessible"),
                        "storage_encrypted": db.get("StorageEncrypted"),
                        "deletion_protection": db.get("DeletionProtection"),
                        "multi_az": db.get("MultiAZ"),
                        "storage_type": db.get("StorageType")
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning RDS instances: {e}")
    return resources
