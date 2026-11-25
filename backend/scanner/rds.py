from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan(session, region="us-east-1"):
    resources = []
    try:
        rds = session.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                db_id = db.get("DBInstanceIdentifier")
                subnet_group = db.get("DBSubnetGroup") or {}
                vpc_id = subnet_group.get("VpcId")
                subnet_ids = [
                    s.get("SubnetIdentifier")
                    for s in subnet_group.get("Subnets", [])
                    if isinstance(s, dict) and s.get("SubnetIdentifier")
                ]
                sec_groups = [
                    sg.get("VpcSecurityGroupId")
                    for sg in db.get("VpcSecurityGroups", [])
                    if isinstance(sg, dict) and sg.get("VpcSecurityGroupId")
                ]

                # Data minimization: explicitly drop Endpoint.Address, MasterUsername,
                # TagList, KmsKeyId, and parameter/option group details.
                resources.append({
                    "id": db_id,
                    "name": db_id,
                    "type": "rds_instance",
                    "service": "RDS",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "db_instance_class": db.get("DBInstanceClass"),
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "status": db.get("DBInstanceStatus"),
                        "publicly_accessible": db.get("PubliclyAccessible"),
                        "storage_encrypted": db.get("StorageEncrypted"),
                        "deletion_protection": db.get("DeletionProtection"),
                        "backup_retention_period": db.get("BackupRetentionPeriod"),
                        "multi_az": db.get("MultiAZ"),
                        "storage_type": db.get("StorageType"),
                        "allocated_storage_gb": db.get("AllocatedStorage"),
                        "vpc_id": vpc_id,
                        "subnet_id": ", ".join(subnet_ids) if subnet_ids else None,
                        "subnet_ids": subnet_ids,
                        "db_subnet_group_name": subnet_group.get("DBSubnetGroupName"),
                        "security_groups": sec_groups,
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
