from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("eks", region_name="us-east-1")
        names = []
        kwargs = {}
        while True:
            response = client.list_clusters(**kwargs)
            names.extend(response.get("clusters", []))
            if "nextToken" not in response:
                break
            kwargs["nextToken"] = response["nextToken"]

        for name in names:
            try:
                cluster = client.describe_cluster(name=name).get("cluster", {})
                
                vpc_config = cluster.get("resourcesVpcConfig", {})
                status = "HEALTHY"
                issues = []
                
                if vpc_config.get("endpointPublicAccess") == True and "0.0.0.0/0" in vpc_config.get("publicAccessCidrs", []):
                    status = "CRITICAL"
                    issues.append("EKS API server endpoint is publicly accessible from any IP")
                    
                resources.append({
                    "id": name,
                    "name": name,
                    "type": "eks_cluster",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "arn": cluster.get("arn"),
                        "status": cluster.get("status"),
                        "version": cluster.get("version"),
                        "created_at": cluster.get("createdAt"),
                        "resources_vpc_config": vpc_config
                    }
                })
            except ClientError as e:
                logging.warning(f"Error describing EKS cluster {name}: {e}")
    except ClientError as e:
        logging.warning(f"Error listing EKS clusters: {e}")
    return resources
