from botocore.exceptions import ClientError
import logging


def _issue(rule_id, severity, title, why, evidence, fix):
    """Return a fully-structured finding dict.

    Every key is always present so the frontend never needs to guard against
    missing fields.
    """
    return {
        "rule_id":  rule_id,
        "severity": severity,   # CRITICAL | WARNING | ORPHANED
        "title":    title,      # Short, non-technical plain-English summary
        "why":      why,        # One sentence explaining the risk
        "evidence": evidence,   # Dict of key→value pairs of actual detected data
        "fix":      fix,        # Actionable remediation step
        # Legacy field kept so nothing existing breaks
        "message":  title,
    }


def evaluate(session, resources: dict) -> dict:
    # Short-circuit: nothing to evaluate if all resource lists are empty
    total = sum(len(v) for v in resources.values() if isinstance(v, list))
    if total == 0:
        return resources

    s3_client = session.client("s3") if session else None

    # Precompute active volume IDs for orphan snapshot check
    active_volume_ids = {v["id"] for v in resources.get("ebs_volumes", [])}

    for r_type, items in resources.items():
        for r in items:
            raw = r.get("raw", {})
            issues = []

            # ------------------------------------------------------------------
            # S3
            # ------------------------------------------------------------------
            if r_type == "s3_buckets":
                bucket_name = r["id"]

                # S3-001 — empty bucket (orphan)
                if raw.get("is_empty"):
                    issues.append(_issue(
                        rule_id="S3-001",
                        severity="ORPHANED",
                        title="Empty S3 bucket",
                        why="An empty bucket serves no purpose and adds clutter to your account.",
                        evidence={"Bucket": bucket_name, "Objects": "0"},
                        fix="If this bucket is no longer needed, delete it from the S3 console.",
                    ))

                # S3-002 — bucket policy makes bucket public
                try:
                    pol_resp = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                    if pol_resp.get("PolicyStatus", {}).get("IsPublic", False):
                        issues.append(_issue(
                            rule_id="S3-002",
                            severity="CRITICAL",
                            title="S3 bucket is publicly accessible via bucket policy",
                            why="Anyone on the internet can read or write objects in this bucket.",
                            evidence={"Bucket": bucket_name, "AccessSource": "Bucket Policy", "PublicAccess": "True"},
                            fix="Remove or update the bucket policy to deny public access. Enable Block Public Access on the bucket.",
                        ))
                except ClientError:
                    pass

                # S3-003 — ACL grants public access
                try:
                    acl_resp = s3_client.get_bucket_acl(Bucket=bucket_name)
                    public_grantees = [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                    ]
                    public_grants = [
                        g.get("Grantee", {}).get("URI", "")
                        for g in acl_resp.get("Grants", [])
                        if g.get("Grantee", {}).get("URI") in public_grantees
                    ]
                    if public_grants:
                        issues.append(_issue(
                            rule_id="S3-003",
                            severity="CRITICAL",
                            title="S3 bucket ACL grants public access",
                            why="The bucket's Access Control List allows read or write access to anyone on the internet.",
                            evidence={"Bucket": bucket_name, "AccessSource": "ACL", "PublicGrantees": ", ".join(public_grants)},
                            fix="Change the bucket ACL to private: S3 → Bucket → Permissions → ACL → Remove public grants.",
                        ))
                except ClientError:
                    pass

                # S3-004 — encryption not enabled
                try:
                    s3_client.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                        issues.append(_issue(
                            rule_id="S3-004",
                            severity="WARNING",
                            title="S3 bucket has no default encryption",
                            why="Objects stored without encryption can be read if the bucket is accessed without authorisation.",
                            evidence={"Bucket": bucket_name, "DefaultEncryption": "Disabled"},
                            fix="Enable default server-side encryption: S3 → Bucket → Properties → Default encryption → Enable (SSE-S3 or SSE-KMS).",
                        ))

                # S3-005 — Block Public Access not fully enabled
                try:
                    pab_resp = s3_client.get_public_access_block(Bucket=bucket_name)
                    config = pab_resp.get("PublicAccessBlockConfiguration", {})
                    missing = [
                        k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
                        if not config.get(k, False)
                    ]
                    if missing:
                        issues.append(_issue(
                            rule_id="S3-005",
                            severity="WARNING",
                            title="S3 Block Public Access is not fully enabled",
                            why="Without all four Block Public Access settings enabled, a future policy or ACL change could accidentally expose this bucket.",
                            evidence={"Bucket": bucket_name, "DisabledSettings": ", ".join(missing)},
                            fix="Enable all four Block Public Access settings: S3 → Bucket → Permissions → Block public access.",
                        ))
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                        issues.append(_issue(
                            rule_id="S3-005",
                            severity="WARNING",
                            title="S3 Block Public Access is not fully enabled",
                            why="Without all four Block Public Access settings enabled, a future policy or ACL change could accidentally expose this bucket.",
                            evidence={"Bucket": bucket_name, "DisabledSettings": "All four settings missing"},
                            fix="Enable all four Block Public Access settings: S3 → Bucket → Permissions → Block public access.",
                        ))

            # ------------------------------------------------------------------
            # Security Groups
            # ------------------------------------------------------------------
            elif r_type == "security_groups":
                dangerous_cidrs = ["0.0.0.0/0", "::/0"]
                for rule in raw.get("ip_permissions", []):
                    protocol  = rule.get("IpProtocol")
                    from_port = rule.get("FromPort")
                    to_port   = rule.get("ToPort")

                    cidrs = [route.get("CidrIp")   for route in rule.get("IpRanges",   [])]
                    cidrs += [route.get("CidrIpv6") for route in rule.get("Ipv6Ranges", [])]

                    for cidr in cidrs:
                        if cidr not in dangerous_cidrs:
                            continue

                        proto_label = "All protocols" if protocol == "-1" else str(protocol).upper()

                        if protocol == "-1":
                            # SG-001 — all traffic open
                            issues.append(_issue(
                                rule_id="SG-001",
                                severity="CRITICAL",
                                title="Security group allows all traffic from the internet",
                                why="Any computer on the internet can attempt to connect to resources using this security group on any port.",
                                evidence={
                                    "SecurityGroup": r["id"],
                                    "Protocol":      "All",
                                    "Ports":         "All",
                                    "Source":        cidr,
                                },
                                fix="Remove the all-traffic inbound rule. Replace it with only the specific ports and protocols your application needs.",
                            ))

                        elif from_port is not None and to_port is not None:
                            if from_port <= 22 <= to_port:
                                # SG-002 — SSH open
                                port_range = "22" if from_port == to_port else f"{from_port}–{to_port}"
                                issues.append(_issue(
                                    rule_id="SG-002",
                                    severity="CRITICAL",
                                    title="SSH port open to the internet",
                                    why="SSH (port 22) allows remote command-line access. Exposing it to the entire internet enables brute-force and credential attacks.",
                                    evidence={
                                        "SecurityGroup": r["id"],
                                        "Port":          port_range,
                                        "Protocol":      proto_label,
                                        "Source":        cidr,
                                    },
                                    fix="Edit the inbound rule: replace 0.0.0.0/0 with your organisation's IP address or CIDR range. Consider AWS Systems Manager Session Manager as a credential-free alternative.",
                                ))

                            elif from_port <= 3389 <= to_port:
                                # SG-003 — RDP open
                                port_range = "3389" if from_port == to_port else f"{from_port}–{to_port}"
                                issues.append(_issue(
                                    rule_id="SG-003",
                                    severity="CRITICAL",
                                    title="RDP port open to the internet",
                                    why="RDP (port 3389) allows remote desktop access to Windows servers. Open RDP is a common ransomware entry point.",
                                    evidence={
                                        "SecurityGroup": r["id"],
                                        "Port":          port_range,
                                        "Protocol":      proto_label,
                                        "Source":        cidr,
                                    },
                                    fix="Edit the inbound rule: replace 0.0.0.0/0 with your organisation's specific IP address. Consider using AWS Systems Manager Session Manager.",
                                ))

            # ------------------------------------------------------------------
            # RDS
            # ------------------------------------------------------------------
            elif r_type == "rds_instances":
                db_id  = raw.get("status", r["id"])
                engine = raw.get("engine", "")

                if raw.get("publicly_accessible"):
                    # RDS-001 — publicly accessible
                    issues.append(_issue(
                        rule_id="RDS-001",
                        severity="CRITICAL",
                        title="Database is accessible from the internet",
                        why="A publicly accessible database can be targeted directly by external attackers. Databases should only be reachable from within your private network.",
                        evidence={
                            "Database":         r["id"],
                            "Engine":           engine,
                            "PubliclyAccessible": "True",
                        },
                        fix="Modify the DB instance: disable 'Publicly accessible'. Ensure your application connects via a private subnet.",
                    ))

                if not raw.get("storage_encrypted"):
                    # RDS-002 — unencrypted storage
                    issues.append(_issue(
                        rule_id="RDS-002",
                        severity="WARNING",
                        title="Database storage is not encrypted",
                        why="Unencrypted database storage can expose sensitive data if the underlying storage is ever accessed outside normal AWS controls.",
                        evidence={
                            "Database":        r["id"],
                            "Engine":          engine,
                            "StorageEncrypted": "False",
                        },
                        fix="Encryption cannot be enabled on a running instance. Take a snapshot, copy it with encryption enabled (snapshot → copy → enable encryption), then restore from the encrypted copy.",
                    ))

                if not raw.get("deletion_protection"):
                    # RDS-003 — no deletion protection
                    issues.append(_issue(
                        rule_id="RDS-003",
                        severity="WARNING",
                        title="Database has no deletion protection",
                        why="Without deletion protection, the database can be permanently deleted by mistake or by a compromised IAM credential.",
                        evidence={
                            "Database":          r["id"],
                            "Engine":            engine,
                            "DeletionProtection": "Disabled",
                        },
                        fix="Enable deletion protection: RDS → Modify DB instance → Enable deletion protection.",
                    ))

            # ------------------------------------------------------------------
            # EBS Volumes
            # ------------------------------------------------------------------
            elif r_type == "ebs_volumes":
                vol_state = str(raw.get("state", "")).lower()
                vol_size  = raw.get("size")

                if not raw.get("encrypted"):
                    # EBS-001 — unencrypted volume
                    issues.append(_issue(
                        rule_id="EBS-001",
                        severity="WARNING",
                        title="EBS volume is not encrypted",
                        why="Unencrypted disk data can be read if the volume is detached and attached to another instance.",
                        evidence={
                            "Volume":    r["id"],
                            "SizeGB":    str(vol_size) if vol_size is not None else "unknown",
                            "Encrypted": "False",
                        },
                        fix="Encryption cannot be toggled on an existing volume. Create a snapshot, copy it with encryption enabled, then create a new volume from the encrypted snapshot.",
                    ))

                if vol_state == "available":
                    # EBS-002 — unattached volume
                    issues.append(_issue(
                        rule_id="EBS-002",
                        severity="ORPHANED",
                        title="Unattached EBS volume",
                        why="This disk is not connected to any server. It may be abandoned, and it will accumulate storage charges until deleted.",
                        evidence={
                            "Volume":    r["id"],
                            "State":     "available (not attached)",
                            "SizeGB":    str(vol_size) if vol_size is not None else "unknown",
                        },
                        fix="If this volume is no longer needed, take a final snapshot for backup and then delete the volume.",
                    ))

            # ------------------------------------------------------------------
            # IAM Roles
            # ------------------------------------------------------------------
            elif r_type == "iam_roles":
                role_name = raw.get("role_name", r["name"])
                role_arn  = raw.get("arn", "")

                # ---- Inline policy checks ----
                seen_wildcard_action = False
                seen_broad_service_action = False
                inline_policies = raw.get("inline_policies", {})
                for policy_name, policy_document in inline_policies.items():
                    statement_list = policy_document.get("Statement", [])
                    if isinstance(statement_list, dict):
                        statement_list = [statement_list]

                    for statement in statement_list:
                        if statement.get("Effect") != "Allow":
                            continue

                        actions = statement.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]

                        resources_list = statement.get("Resource", [])
                        if isinstance(resources_list, str):
                            resources_list = [resources_list]

                        # IAM-001 — wildcard action
                        if ("*" in actions or "iam:*" in actions) and not seen_wildcard_action:
                            seen_wildcard_action = True
                            issues.append(_issue(
                                rule_id="IAM-001",
                                severity="CRITICAL",
                                title="IAM role has unrestricted wildcard permissions",
                                why="Action: * grants every AWS permission that exists, including deleting resources and modifying billing. This violates the principle of least privilege.",
                                evidence={
                                    "Role":       role_name,
                                    "Policy":     policy_name,
                                    "Action":     "*",
                                    "Resource":   ", ".join(resources_list[:5]),
                                },
                                fix="Replace 'Action: *' with only the specific actions this role actually needs. Consult IAM Access Analyzer to identify used permissions.",
                            ))

                        # IAM-006 — service-level full wildcard action (e.g., s3:*, ec2:*, dynamodb:*)
                        broad_service_actions = [a for a in actions if a.endswith(":*") and a not in ("iam:*", "*")]
                        if broad_service_actions and "*" in resources_list and not seen_wildcard_action and not seen_broad_service_action:
                            seen_broad_service_action = True
                            issues.append(_issue(
                                rule_id="IAM-006",
                                severity="WARNING",
                                title="IAM role grants broad service-level wildcards",
                                why="Full service wildcards (e.g. s3:*, ec2:*) grant all administrative, read, and write operations across the entire service without resource restriction.",
                                evidence={
                                    "Role":     role_name,
                                    "Policy":   policy_name,
                                    "Actions":  ", ".join(broad_service_actions[:5]),
                                    "Resource": "*",
                                },
                                fix="Replace service wildcards with the specific API actions required (e.g., s3:GetObject, ec2:DescribeInstances) and restrict resource ARNs.",
                            ))

                        # IAM-002 — broad resource scope (non-wildcard action on *)
                        if "*" in resources_list and any(":" in a for a in actions) and not any(a == "*" or a == "iam:*" or a.endswith(":*") for a in actions):
                            issues.append(_issue(
                                rule_id="IAM-002",
                                severity="WARNING",
                                title="IAM role permissions apply to all resources",
                                why="Granting permissions on Resource: * means the role can act on every resource of that type in the account, not just the ones it needs.",
                                evidence={
                                    "Role":     role_name,
                                    "Policy":   policy_name,
                                    "Actions":  ", ".join(actions[:10]),
                                    "Resource": "*",
                                },
                                fix="Narrow the Resource field to specific ARNs of the resources this role needs to access.",
                            ))

                # ---- Attached managed policy checks ----
                attached_policies = raw.get("attached_managed_policies", [])
                dangerous_managed = {
                    "arn:aws:iam::aws:policy/AdministratorAccess": ("IAM-003", "CRITICAL",
                        "IAM role has AdministratorAccess managed policy",
                        "AdministratorAccess grants full, unrestricted access to every AWS service and resource in the account.",
                        "Detach AdministratorAccess from this role and replace it with a custom policy granting only necessary permissions."),
                    "arn:aws:iam::aws:policy/IAMFullAccess": ("IAM-004", "WARNING",
                        "IAM role has IAMFullAccess managed policy",
                        "IAMFullAccess allows this role to create or modify any IAM user, role, or policy — effectively enabling privilege escalation.",
                        "Detach IAMFullAccess and scope permissions to only read or modify specific roles."),
                    "arn:aws:iam::aws:policy/PowerUserAccess": ("IAM-007", "WARNING",
                        "IAM role has PowerUserAccess managed policy",
                        "PowerUserAccess provides full access to AWS services and resources except IAM management, which is excessively broad for production roles.",
                        "Replace PowerUserAccess with a tailored policy that specifies only required service actions."),
                }
                for pol in attached_policies:
                    pol_arn = pol.get("PolicyArn", "")
                    pol_name = pol.get("PolicyName", pol_arn)
                    if pol_arn in dangerous_managed:
                        rule_id, sev, title, why, fix_text = dangerous_managed[pol_arn]
                        issues.append(_issue(
                            rule_id=rule_id,
                            severity=sev,
                            title=title,
                            why=why,
                            evidence={
                                "Role":         role_name,
                                "PolicyName":   pol_name,
                                "PolicyArn":    pol_arn,
                            },
                            fix=fix_text,
                        ))

                # ---- Trust relationship checks ----
                trust_doc = raw.get("trust_policy", {})
                trust_statements = trust_doc.get("Statement", [])
                if isinstance(trust_statements, dict):
                    trust_statements = [trust_statements]
                for stmt in trust_statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal", {})
                    # Principal: "*"  or  Principal: {"AWS": "*"}
                    is_public = (
                        principal == "*"
                        or (isinstance(principal, dict) and principal.get("AWS") == "*")
                        or (isinstance(principal, dict) and principal.get("Service") == "*")
                    )
                    if is_public:
                        issues.append(_issue(
                            rule_id="IAM-005",
                            severity="CRITICAL",
                            title="IAM role can be assumed by anyone",
                            why="A trust policy with Principal: * allows any AWS account or entity to assume this role and inherit all its permissions.",
                            evidence={
                                "Role":      role_name,
                                "Principal": "*",
                            },
                            fix="Update the trust policy: replace Principal: * with the specific AWS account ID, role ARN, or service that needs to assume this role.",
                        ))
                        break

                    # Check for cross-account trust without external ID condition (IAM-008)
                    if isinstance(principal, dict) and "AWS" in principal:
                        aws_p = principal["AWS"]
                        aws_principals = aws_p if isinstance(aws_p, list) else [aws_p]
                        condition = stmt.get("Condition", {})
                        has_ext_id = any(
                            k in ("StringEquals", "StringLike") and any("sts:ExternalId" in str(ck) for ck in cv.keys())
                            for k, cv in condition.items() if isinstance(cv, dict)
                        )
                        # Check if any principal points to an external AWS account (root or role)
                        for p_arn in aws_principals:
                            if isinstance(p_arn, str) and (":root" in p_arn or (p_arn.isdigit() and len(p_arn) == 12)):
                                if not has_ext_id and not is_public:
                                    issues.append(_issue(
                                        rule_id="IAM-008",
                                        severity="WARNING",
                                        title="Cross-account trust policy missing ExternalId condition",
                                        why="Assuming roles across AWS accounts without requiring an ExternalId makes the role susceptible to confused deputy attacks.",
                                        evidence={
                                            "Role":             role_name,
                                            "TrustedAccount":   p_arn,
                                            "MissingCondition": "sts:ExternalId",
                                        },
                                        fix="Add a Condition block requiring 'sts:ExternalId' to ensure third parties cannot assume this role without a unique secret identifier.",
                                    ))
                                    break

            # ------------------------------------------------------------------
            # EC2 Instances
            # ------------------------------------------------------------------
            elif r_type == "ec2_instances":
                ec2_state = str(raw.get("state", "")).lower()
                if ec2_state == "stopped":
                    # EC2-001 — stopped instance
                    issues.append(_issue(
                        rule_id="EC2-001",
                        severity="ORPHANED",
                        title="EC2 instance is stopped",
                        why="Stopped instances still accumulate charges for attached EBS storage and Elastic IPs. If no longer needed, they should be terminated.",
                        evidence={
                            "Instance":     r["id"],
                            "InstanceType": raw.get("instance_type", "unknown"),
                            "State":        "stopped",
                        },
                        fix="If this instance is no longer needed, terminate it. If it may be reused, start it up. Stopped instances still incur EBS storage charges.",
                    ))

            # ------------------------------------------------------------------
            # Elastic IPs
            # ------------------------------------------------------------------
            elif r_type == "elastic_ips":
                if not raw.get("association_id"):
                    # EIP-001 — unassociated Elastic IP
                    issues.append(_issue(
                        rule_id="EIP-001",
                        severity="ORPHANED",
                        title="Elastic IP is not attached to any resource",
                        why="Unassociated Elastic IPs are billed hourly even while idle. They are also wasting a limited pool of public IPs.",
                        evidence={
                            "ElasticIP": r["id"],
                            "AssociationId": "None",
                        },
                        fix="If this IP is no longer needed, release it from the EC2 console (Elastic IPs → Actions → Release).",
                    ))

            # ------------------------------------------------------------------
            # Snapshots
            # ------------------------------------------------------------------
            elif r_type == "snapshots":
                vol_id = raw.get("volume_id")
                if vol_id and vol_id not in active_volume_ids:
                    # SNAP-001 — orphan snapshot
                    issues.append(_issue(
                        rule_id="SNAP-001",
                        severity="ORPHANED",
                        title="Snapshot source volume no longer exists",
                        why="The EBS volume this snapshot was created from has been deleted. The snapshot may be abandoned and is accumulating storage charges.",
                        evidence={
                            "Snapshot":      r["id"],
                            "SourceVolumeId": vol_id,
                            "VolumeStatus":  "deleted or not found",
                        },
                        fix="Review whether this snapshot is still needed for disaster recovery or audit purposes. If not, delete it to stop storage charges.",
                    ))

            # ------------------------------------------------------------------
            # Deduplication — same rule_id only once per resource
            # ------------------------------------------------------------------
            seen_rule_ids = set()
            unique_issues = []
            for issue in issues:
                if issue["rule_id"] not in seen_rule_ids:
                    seen_rule_ids.add(issue["rule_id"])
                    unique_issues.append(issue)

            r["issues"] = unique_issues

            # Apply status priority rule (unchanged)
            has_crit = any(i["severity"] == "CRITICAL"  for i in r["issues"])
            has_warn = any(i["severity"] == "WARNING"   for i in r["issues"])
            has_orph = any(i["severity"] == "ORPHANED"  for i in r["issues"])

            if has_crit:
                r["status"] = "CRITICAL"
            elif has_warn:
                r["status"] = "WARNING"
            elif has_orph:
                r["status"] = "ORPHANED"
            else:
                r["status"] = "HEALTHY"

    return resources
