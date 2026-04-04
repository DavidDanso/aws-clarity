from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        rds = session.client("rds", region_name="us-east-1")
        paginator = rds.get_paginator("describe_db_clusters")
        pages = paginator.paginate()
        for page in pages:
            for cluster in page.get("DBClusters", []):
                engine = cluster.get("Engine", "")
                if not engine.startswith("aurora"):
                    continue
                    
                cluster_id = cluster.get("DBClusterIdentifier")
                storage_encrypted = cluster.get("StorageEncrypted", False)
                deletion_protection = cluster.get("DeletionProtection", False)
                
                status = "HEALTHY"
                issues = []
                if not storage_encrypted:
                    status = "WARNING"
                    issues.append("Aurora cluster storage is not encrypted")
                    
                if not deletion_protection:
                    status = "WARNING"
                    issues.append("Deletion protection is disabled")
                    
                resources.append({
                    "id": cluster_id,
                    "name": cluster_id,
                    "type": "aurora_cluster",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "engine": engine,
                        "engine_version": cluster.get("EngineVersion"),
                        "status": cluster.get("Status"),
                        "storage_encrypted": storage_encrypted,
                        "deletion_protection": deletion_protection,
                        "multi_az": cluster.get("MultiAZ")
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning Aurora clusters: {e}")
    return resources
