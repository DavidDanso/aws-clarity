from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("ecs", region_name="us-east-1")
        arns = []
        kwargs = {}
        while True:
            response = client.list_clusters(**kwargs)
            arns.extend(response.get("clusterArns", []))
            if "nextToken" not in response:
                break
            kwargs["nextToken"] = response["nextToken"]

        # Call describe_clusters(clusters=batch, include=["STATISTICS"]) in batches of 100
        for i in range(0, len(arns), 100):
            batch = arns[i:i+100]
            try:
                desc_res = client.describe_clusters(clusters=batch, include=["STATISTICS"])
                for cluster in desc_res.get("clusters", []):
                    name = cluster.get("clusterName")
                    arn = cluster.get("clusterArn")
                    
                    registered = cluster.get("registeredContainerInstancesCount", 0)
                    running = cluster.get("runningTasksCount", 0)
                    active = cluster.get("activeServicesCount", 0)
                    
                    status = "HEALTHY"
                    issues = []
                    
                    if registered == 0 and active == 0:
                        status = "ORPHANED"
                        issues.append("ECS cluster has no registered instances or active services")
                    
                    resources.append({
                        "id": arn,
                        "name": name,
                        "type": "ecs_cluster",
                        "status": status,
                        "issues": issues,
                        "raw": {
                            "status": cluster.get("status"),
                            "registered_container_instances_count": registered,
                            "running_tasks_count": running,
                            "active_services_count": active
                        }
                    })
            except ClientError as e:
                logging.warning(f"Error describing ECS clusters: {e}")

    except ClientError as e:
        logging.warning(f"Error listing ECS clusters: {e}")
    return resources
