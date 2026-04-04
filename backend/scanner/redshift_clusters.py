from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        redshift = session.client("redshift", region_name="us-east-1")
        paginator = redshift.get_paginator("describe_clusters")
        pages = paginator.paginate()
        for page in pages:
            for cluster in page.get("Clusters", []):
                cluster_id = cluster.get("ClusterIdentifier")
                public = cluster.get("PubliclyAccessible", False)
                encrypted = cluster.get("Encrypted", False)
                
                status = "HEALTHY"
                issues = []
                
                if public:
                    status = "CRITICAL"
                    issues.append("Redshift cluster is publicly accessible from the internet")
                if not encrypted:
                    if status != "CRITICAL":
                        status = "WARNING"
                    issues.append("Cluster is not encrypted at rest")
                    
                resources.append({
                    "id": cluster_id,
                    "name": cluster_id,
                    "type": "redshift_cluster",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "node_type": cluster.get("NodeType"),
                        "cluster_status": cluster.get("ClusterStatus"),
                        "encrypted": encrypted,
                        "publicly_accessible": public,
                        "number_of_nodes": cluster.get("NumberOfNodes")
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning Redshift clusters: {e}")
    return resources
