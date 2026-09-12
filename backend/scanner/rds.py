from botocore.exceptions import ClientError
import logging

def scan(session, region="us-east-1"):
    resources = []
    try:
        rds = session.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")
        pages = paginator.paginate()
        for page in pages:
            for db in page.get("DBInstances", []):
                db_id = db.get("DBInstanceIdentifier")
                name = db_id 
                subnet_group = db.get("DBSubnetGroup") or {}
                vpc_id = subnet_group.get("VpcId")
                subnet_ids = [s.get("SubnetIdentifier") for s in subnet_group.get("Subnets", []) if s.get("SubnetIdentifier")]
                sec_groups = [sg.get("VpcSecurityGroupId") for sg in db.get("VpcSecurityGroups", []) if sg.get("VpcSecurityGroupId")]

                resources.append({
                    "id": db_id,
                    "name": name,
                    "type": "rds_instance",
                    "status": "HEALTHY",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "db_instance_class": db.get("DBInstanceClass"),
                        "engine": db.get("Engine"),
                        "status": db.get("DBInstanceStatus"),
                        "publicly_accessible": db.get("PubliclyAccessible"),
                        "storage_encrypted": db.get("StorageEncrypted"),
                        "deletion_protection": db.get("DeletionProtection"),
                        "multi_az": db.get("MultiAZ"),
                        "storage_type": db.get("StorageType"),
                        "vpc_id": vpc_id,
                        "subnet_id": ", ".join(subnet_ids) if subnet_ids else None,
                        "subnet_ids": subnet_ids,
                        "db_subnet_group_name": subnet_group.get("DBSubnetGroupName"),
                        "security_groups": sec_groups,
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning RDS instances: {e}")
    return resources
