from botocore.exceptions import ClientError
import logging

def evaluate(session, resources: dict) -> dict:
    s3_client = session.client("s3")
    
    # Precompute active volumes
    active_volume_ids = {v["id"] for v in resources.get("ebs_volumes", [])}
    
    for r_type, items in resources.items():
        for r in items:
            raw = r.get("raw", {})
            issues = []
            
            if r_type == "s3_buckets":
                bucket_name = r["id"]
                
                # Check empty orphan
                if raw.get("is_empty"):
                    issues.append({
                        "severity": "ORPHANED",
                        "message": "S3 bucket empty (orphan)",
                        "fix": "If this bucket is no longer needed, delete it. Empty buckets don't incur storage costs but are clutter."
                    })
                
                try:
                    pol_resp = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                    if pol_resp.get("PolicyStatus", {}).get("IsPublic", False):
                        issues.append({
                            "severity": "CRITICAL",
                            "message": "S3 bucket is publicly accessible (policy)",
                            "fix": "Remove the bucket policy or update it to deny public access. Enable Block Public Access settings on the bucket."
                        })
                except ClientError as e:
                    pass
                    
                try:
                    acl_resp = s3_client.get_bucket_acl(Bucket=bucket_name)
                    public_grantees = [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                    ]
                    acl_is_public = any(
                        grant.get("Grantee", {}).get("URI") in public_grantees
                        for grant in acl_resp.get("Grants", [])
                    )
                    if acl_is_public:
                        issues.append({
                            "severity": "CRITICAL",
                            "message": "S3 bucket ACL is public",
                            "fix": "Change the bucket ACL to private. Go to S3 → Bucket → Permissions → ACL and remove public grants."
                        })
                except ClientError:
                    pass
                
                try:
                    s3_client.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                        issues.append({
                            "severity": "WARNING",
                            "message": "S3 bucket encryption disabled",
                            "fix": "Enable default server-side encryption. Go to S3 → Bucket → Properties → Default encryption → Enable."
                        })
                        
                try:
                    pab_resp = s3_client.get_public_access_block(Bucket=bucket_name)
                    config = pab_resp.get("PublicAccessBlockConfiguration", {})
                    fully_blocked = all([
                        config.get("BlockPublicAcls", False),
                        config.get("IgnorePublicAcls", False),
                        config.get("BlockPublicPolicy", False),
                        config.get("RestrictPublicBuckets", False)
                    ])
                    if not fully_blocked:
                        issues.append({
                            "severity": "WARNING",
                            "message": "S3 public access block not fully enabled",
                            "fix": "Enable all four Block Public Access settings. Go to S3 → Bucket → Permissions → Block public access."
                        })
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                        issues.append({
                            "severity": "WARNING",
                            "message": "S3 public access block not fully enabled",
                            "fix": "Enable all four Block Public Access settings. Go to S3 → Bucket → Permissions → Block public access."
                        })
                        
            elif r_type == "security_groups":
                dangerous_cidrs = ["0.0.0.0/0", "::/0"]
                for rule in raw.get("ip_permissions", []):
                    protocol = rule.get("IpProtocol")
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    
                    cidrs = [route.get("CidrIp") for route in rule.get("IpRanges", [])]
                    cidrs += [route.get("CidrIpv6") for route in rule.get("Ipv6Ranges", [])]
                    
                    for cidr in cidrs:
                        if cidr in dangerous_cidrs:
                            if protocol == "-1":
                                issues.append({
                                    "severity": "CRITICAL",
                                    "message": "Security group: all traffic open to internet",
                                    "fix": "Remove the all-traffic inbound rule and replace it with only the ports and protocols your application actually needs."
                                })
                            elif from_port is not None and to_port is not None:
                                if from_port <= 22 <= to_port:
                                    issues.append({
                                        "severity": "CRITICAL",
                                        "message": "Security group: SSH open to internet",
                                        "fix": "Edit the inbound rule for port 22. Replace 0.0.0.0/0 with your IP address, or switch to AWS Systems Manager Session Manager instead."
                                    })
                                elif from_port <= 3389 <= to_port:
                                    issues.append({
                                        "severity": "CRITICAL",
                                        "message": "Security group: RDP open to internet",
                                        "fix": "Edit the inbound rule for port 3389. Replace 0.0.0.0/0 with your specific IP address."
                                    })
                                    
            elif r_type == "rds_instances":
                if raw.get("publicly_accessible"):
                    issues.append({
                        "severity": "CRITICAL",
                        "message": "RDS publicly accessible",
                        "fix": "Modify the DB instance and disable the 'Publicly accessible' option. Ensure your app accesses RDS through a private subnet."
                    })
                if not raw.get("storage_encrypted"):
                    issues.append({
                        "severity": "WARNING",
                        "message": "RDS storage not encrypted",
                        "fix": "Encryption cannot be enabled on a running instance. Take a snapshot, copy it with encryption enabled, then restore."
                    })
                if not raw.get("deletion_protection"):
                    issues.append({
                        "severity": "WARNING",
                        "message": "RDS deletion protection disabled",
                        "fix": "Enable deletion protection. Go to RDS → Modify DB instance → Enable deletion protection."
                    })
                    
            elif r_type == "ebs_volumes":
                if not raw.get("encrypted"):
                    issues.append({
                        "severity": "WARNING",
                        "message": "EBS volume not encrypted",
                        "fix": "Encrypted cannot be toggled on existing volumes. Create a snapshot, copy it with encryption, and create a new volume from it."
                    })
                if str(raw.get("state")).lower() == "available":
                    issues.append({
                        "severity": "ORPHANED",
                        "message": "EBS unattached (orphan)",
                        "fix": "Snapshot the volume for backup if needed, then delete it to stop incurring charges."
                    })
                    
            elif r_type == "iam_roles":
                policies = raw.get("inline_policies", {})
                for policy_name, policy_document in policies.items():
                    statement_list = policy_document.get("Statement", [])
                    if isinstance(statement_list, dict):
                        statement_list = [statement_list]
                    for statement in statement_list:
                        if statement.get("Effect") != "Allow":
                            continue
                            
                        actions = statement.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                            
                        if "*" in actions or "iam:*" in actions:
                            issues.append({
                                "severity": "CRITICAL",
                                "message": "IAM wildcard action",
                                "fix": "Replace the Action: * with only the specific actions this role requires. Follow the principle of least privilege."
                            })
                            
                        resources_list = statement.get("Resource", [])
                        if isinstance(resources_list, str):
                            resources_list = [resources_list]
                            
                        if "*" in resources_list and any(":" in a for a in actions):
                            issues.append({
                                "severity": "WARNING",
                                "message": "IAM broad resource scope",
                                "fix": "Narrow the Resource field from * to the specific ARNs this role needs to access."
                            })
                            
            elif r_type == "ec2_instances":
                if str(raw.get("state")).lower() == "stopped":
                    issues.append({
                        "severity": "ORPHANED",
                        "message": "EC2 stopped (orphan)",
                        "fix": "If this instance is no longer needed, terminate it. Stopped instances still incur EBS storage charges. If needed, start it up."
                    })
                    
            elif r_type == "elastic_ips":
                if not raw.get("association_id"):
                    issues.append({
                        "severity": "ORPHANED",
                        "message": "Elastic IP unassociated (orphan)",
                        "fix": "Unassociated Elastic IPs incur hourly charges. Release it from the EC2 console if it's no longer needed."
                    })
                    
            elif r_type == "snapshots":
                vol_id = raw.get("volume_id")
                if vol_id and vol_id not in active_volume_ids:
                    issues.append({
                        "severity": "ORPHANED",
                        "message": "Snapshot source volume deleted (orphan)",
                        "fix": "Review whether this snapshot is still needed. If not, delete it to eliminate storage costs."
                    })

            # Ensure unique issues based on message
            unique_issues = {i["message"]: i for i in issues}.values()
            r["issues"] = list(unique_issues)
            
            # Apply status priority rule
            has_crit = any(i["severity"] == "CRITICAL" for i in r["issues"])
            has_warn = any(i["severity"] == "WARNING" for i in r["issues"])
            has_orph = any(i["severity"] == "ORPHANED" for i in r["issues"])
            
            if has_crit:
                r["status"] = "CRITICAL"
            elif has_warn:
                r["status"] = "WARNING"
            elif has_orph:
                r["status"] = "ORPHANED"
            else:
                r["status"] = "HEALTHY"

    return resources
