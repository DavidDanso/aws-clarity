from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        elasticache = session.client("elasticache", region_name="us-east-1")
        paginator = elasticache.get_paginator("describe_cache_clusters")
        pages = paginator.paginate(ShowCacheNodeInfo=True)
        for page in pages:
            for cluster in page.get("CacheClusters", []):
                cluster_id = cluster.get("CacheClusterId")
                at_rest = cluster.get("AtRestEncryptionEnabled", False)
                transit = cluster.get("TransitEncryptionEnabled", False)
                
                status = "HEALTHY"
                issues = []
                
                if not at_rest:
                    status = "WARNING"
                    issues.append("Cluster is not encrypted at rest")
                
                if not transit:
                    status = "WARNING"
                    issues.append("Cluster does not use in-transit encryption")
                
                resources.append({
                    "id": cluster_id,
                    "name": cluster_id,
                    "type": "elasticache_cluster",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "engine": cluster.get("Engine"),
                        "cache_node_type": cluster.get("CacheNodeType"),
                        "cache_cluster_status": cluster.get("CacheClusterStatus"),
                        "num_cache_nodes": cluster.get("NumCacheNodes"),
                        "at_rest_encryption_enabled": at_rest,
                        "transit_encryption_enabled": transit
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning ElastiCache clusters: {e}")
    return resources
