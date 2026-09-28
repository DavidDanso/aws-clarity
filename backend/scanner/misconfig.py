from botocore.exceptions import ClientError
import logging


RULE_METADATA = {
    "S3-001": {
        "what_found": "Bucket contains 0 objects and has no active storage usage.",
        "what_checked": "Queried S3 bucket object count and storage usage.",
    },
    "S3-002": {
        "what_found": "Bucket policy explicitly allows public read or write access from the internet.",
        "what_checked": "Queried S3 GetBucketPolicyStatus API to evaluate policy public access.",
    },
    "S3-003": {
        "what_found": "Bucket Access Control List (ACL) grants permissions to AllUsers or AuthenticatedUsers.",
        "what_checked": "Queried S3 GetBucketAcl API and inspected grantee URI definitions.",
    },
    "S3-004": {
        "what_found": "Server-side encryption is not enabled by default for objects stored in this bucket.",
        "what_checked": "Queried S3 GetBucketEncryption API configuration.",
    },
    "S3-005": {
        "what_found": "One or more of the four S3 Block Public Access controls are disabled.",
        "what_checked": "Queried S3 GetPublicAccessBlock configuration for all 4 security flags.",
    },
    "SG-001": {
        "what_found": "Inbound firewall rule allows all protocols (-1) and all ports from 0.0.0.0/0 or ::/0.",
        "what_checked": "Evaluated Security Group ingress IP permissions for unrestricted CIDR routes across all protocols.",
    },
    "SG-002": {
        "what_found": "Inbound SSH access is allowed from 0.0.0.0/0 or ::/0 on port 22.",
        "what_checked": "Evaluated Security Group ingress IP permissions for port 22 with unrestricted CIDR sources.",
    },
    "SG-003": {
        "what_found": "Inbound RDP access is allowed from 0.0.0.0/0 or ::/0 on port 3389.",
        "what_checked": "Evaluated Security Group ingress IP permissions for port 3389 with unrestricted CIDR sources.",
    },
    "RDS-001": {
        "what_found": "RDS instance PubliclyAccessible flag is set to true and placed in a public subnet.",
        "what_checked": "Inspected RDS DescribeDBInstances PubliclyAccessible configuration.",
    },
    "RDS-002": {
        "what_found": "RDS instance storage encryption is disabled.",
        "what_checked": "Inspected RDS DescribeDBInstances StorageEncrypted attribute.",
    },
    "RDS-003": {
        "what_found": "Deletion protection is disabled on this RDS instance.",
        "what_checked": "Inspected RDS DescribeDBInstances DeletionProtection attribute.",
    },
    "EBS-001": {
        "what_found": "EBS volume block storage has encryption disabled.",
        "what_checked": "Inspected EC2 DescribeVolumes Encrypted attribute.",
    },
    "EBS-002": {
        "what_found": "EBS volume is in 'available' state and not attached to any EC2 instance.",
        "what_checked": "Inspected EC2 DescribeVolumes State and Attachments list.",
    },
    "IAM-001": {
        "what_found": "Inline IAM policy statement contains Action: * or Action: iam:* with Effect: Allow.",
        "what_checked": "Parsed IAM role inline policy documents for unrestricted Action: * statements.",
    },
    "IAM-002": {
        "what_found": "IAM policy statements grant actions with Resource: * without resource scoping.",
        "what_checked": "Parsed IAM role inline policy documents for statements with Resource: *.",
    },
    "IAM-003": {
        "what_found": "AWS managed policy AdministratorAccess is attached to this IAM role.",
        "what_checked": "Inspected IAM ListAttachedRolePolicies for AdministratorAccess.",
    },
    "IAM-004": {
        "what_found": "AWS managed policy IAMFullAccess is attached to this IAM role.",
        "what_checked": "Inspected IAM ListAttachedRolePolicies for IAMFullAccess.",
    },
    "IAM-005": {
        "what_found": "Role trust policy allows Principal: * or AWS: * to assume the role.",
        "what_checked": "Parsed AssumeRolePolicyDocument for wildcard Principal definitions.",
    },
    "IAM-006": {
        "what_found": "IAM policy statement grants full wildcard actions across an entire service (e.g. s3:*, ec2:*).",
        "what_checked": "Parsed IAM policy statements for actions ending with :* combined with Resource: *.",
    },
    "IAM-007": {
        "what_found": "AWS managed policy PowerUserAccess is attached to this IAM role.",
        "what_checked": "Inspected IAM ListAttachedRolePolicies for PowerUserAccess.",
    },
    "IAM-008": {
        "what_found": "Cross-account trust relationship does not enforce an sts:ExternalId condition.",
        "what_checked": "Inspected AssumeRolePolicyDocument cross-account principals for sts:ExternalId conditions.",
    },
    "EC2-001": {
        "what_found": "EC2 instance is in 'stopped' state while retaining attached storage and IPs.",
        "what_checked": "Inspected EC2 DescribeInstances instance state.",
    },
    "EIP-001": {
        "what_found": "Elastic IP address has no active AssociationId or attached network interface.",
        "what_checked": "Inspected EC2 DescribeAddresses association_id field.",
    },
    "SNAP-001": {
        "what_found": "The EBS volume from which this snapshot was taken has been deleted or cannot be found.",
        "what_checked": "Cross-referenced Snapshot VolumeId against active EBS volumes in the account.",
    },
    "ECR-001": {
        "what_found": "ECR repository allows image tags to be overwritten by new pushes.",
        "what_checked": "Inspected ECR DescribeRepositories imageTagMutability configuration.",
        "category": "Security",
    },
    "ECR-002": {
        "what_found": "Automatic vulnerability scanning on push is not enabled for this repository.",
        "what_checked": "Inspected ECR DescribeRepositories imageScanningConfiguration scanOnPush flag.",
        "category": "Security",
    },
    "EKS-001": {
        "what_found": "Kubernetes API server endpoint is publicly accessible from any IP address (0.0.0.0/0).",
        "what_checked": "Inspected EKS DescribeCluster resourcesVpcConfig endpointPublicAccess and publicAccessCidrs.",
        "category": "Security",
    },
    "RS-001": {
        "what_found": "Redshift cluster has PubliclyAccessible set to true and can receive connections from the internet.",
        "what_checked": "Inspected Redshift DescribeClusters PubliclyAccessible attribute.",
        "category": "Security",
    },
    "RS-002": {
        "what_found": "Redshift cluster data warehouse storage is not encrypted at rest.",
        "what_checked": "Inspected Redshift DescribeClusters Encrypted attribute.",
        "category": "Security",
    },
    "AUR-001": {
        "what_found": "Aurora database cluster storage encryption is disabled.",
        "what_checked": "Inspected RDS DescribeDBClusters StorageEncrypted attribute.",
        "category": "Security",
    },
    "AUR-002": {
        "what_found": "Accidental deletion protection is disabled on this Aurora cluster.",
        "what_checked": "Inspected RDS DescribeDBClusters DeletionProtection attribute.",
        "category": "Reliability",
    },
    "EC-001": {
        "what_found": "In-memory cache cluster is not encrypted at rest.",
        "what_checked": "Inspected ElastiCache DescribeCacheClusters AtRestEncryptionEnabled flag.",
        "category": "Security",
    },
    "EC-002": {
        "what_found": "Transit encryption (TLS) is disabled for cache communication.",
        "what_checked": "Inspected ElastiCache DescribeCacheClusters TransitEncryptionEnabled flag.",
        "category": "Security",
    },
    "DDB-001": {
        "what_found": "Table uses default AWS-owned key rather than customer-managed KMS encryption (KMS CMK).",
        "what_checked": "Inspected DynamoDB DescribeTable SSEDescription configuration.",
        "category": "Security",
    },
    "SEC-001": {
        "what_found": "Automatic secret rotation is not enabled for this secret.",
        "what_checked": "Inspected Secrets Manager ListSecrets RotationEnabled attribute.",
        "category": "Security",
    },
    "SEC-002": {
        "what_found": "Secret is encrypted with the default aws/secretsmanager key rather than a customer-managed KMS key.",
        "what_checked": "Inspected Secrets Manager ListSecrets KmsKeyId attribute.",
        "category": "Security",
    },
    "SQS-001": {
        "what_found": "SQS message queue does not have server-side encryption enabled with a KMS key.",
        "what_checked": "Inspected SQS GetQueueAttributes KmsMasterKeyId attribute.",
        "category": "Security",
    },
    "SNS-001": {
        "what_found": "SNS topic is not encrypted with a customer-managed KMS key.",
        "what_checked": "Inspected SNS GetTopicAttributes KmsMasterKeyId attribute.",
        "category": "Security",
    },
    "NAT-001": {
        "what_found": "NAT Gateway is in a failed state and cannot route outbound internet traffic.",
        "what_checked": "Inspected EC2 DescribeNatGateways State attribute.",
        "category": "Reliability",
    },
    "NAT-002": {
        "what_found": "Active NAT Gateway configuration generates continuous hourly availability charges.",
        "what_checked": "Inspected EC2 DescribeNatGateways State and SubnetId.",
        "category": "Cost Risk",
    },
    "ASG-001": {
        "what_found": "Auto Scaling Group has both desired capacity and minimum size set to 0.",
        "what_checked": "Inspected AutoScaling DescribeAutoScalingGroups DesiredCapacity and MinSize.",
        "category": "Orphaned",
    },
    "ECS-001": {
        "what_found": "ECS cluster is empty with 0 registered container instances and 0 active services.",
        "what_checked": "Inspected ECS DescribeClusters registeredContainerInstancesCount and activeServicesCount.",
        "category": "Orphaned",
    },
    "IGW-001": {
        "what_found": "Internet Gateway exists but has no active VPC attachments.",
        "what_checked": "Inspected EC2 DescribeInternetGateways Attachments array.",
        "category": "Orphaned",
    },
    "CW-001": {
        "what_found": "Alarm actions are disabled; this alarm will not execute notifications when triggered.",
        "what_checked": "Inspected CloudWatch DescribeAlarms ActionsEnabled flag.",
        "category": "Reliability",
    },
    "CW-002": {
        "what_found": "Alarm state is INSUFFICIENT_DATA and cannot determine health.",
        "what_checked": "Inspected CloudWatch DescribeAlarms StateValue attribute.",
        "category": "Reliability",
    },
    "EV-001": {
        "what_found": "EventBridge rule state is DISABLED and is not processing events or schedules.",
        "what_checked": "Inspected EventBridge ListRules State attribute.",
        "category": "Orphaned",
    },
    "CFN-001": {
        "what_found": "Stack status indicates failed provisioning, rollback, or failed deletion.",
        "what_checked": "Inspected CloudFormation DescribeStacks StackStatus attribute.",
        "category": "Orphaned",
    },
    "CFN-002": {
        "what_found": "Termination protection is not enabled on this CloudFormation stack.",
        "what_checked": "Inspected CloudFormation DescribeStacks EnableTerminationProtection attribute.",
        "category": "Reliability",
    },
    "LAM-001": {
        "what_found": "Function code and configuration have not been updated in over 90 days.",
        "what_checked": "Inspected Lambda ListFunctions LastModified timestamp.",
        "category": "Hygiene",
    },
    "ELB-001": {
        "what_found": "Load balancer scheme is configured as internet-facing with a public DNS name.",
        "what_checked": "Inspected Elastic Load Balancing DescribeLoadBalancers Scheme attribute.",
        "category": "Security",
    },
    "VPC-001": {
        "what_found": "This VPC is the AWS default VPC with standard public subnets and open routing.",
        "what_checked": "Inspected EC2 DescribeVpcs IsDefault flag.",
        "category": "Security",
    },
}


def _issue(rule_id, severity, title, why, evidence, fix, what_found=None, what_checked=None, resource_type=None, resource_id=None, category=None):
    """Return a fully-structured finding dict with explainable evidence.

    Every key is always present so the frontend never needs to guard against
    missing fields.
    """
    meta = RULE_METADATA.get(rule_id, {})
    resolved_what_found = what_found or meta.get("what_found") or title
    resolved_what_checked = what_checked or meta.get("what_checked") or "Inspected AWS resource configuration."
    resolved_category = category or meta.get("category") or "Security"

    item = {
        "rule_id":      rule_id,
        "severity":     severity,   # CRITICAL | WARNING | ORPHANED
        "title":        title,      # Short, non-technical plain-English summary
        "what_found":   resolved_what_found,
        "why":          why,        # One sentence explaining the risk
        "what_checked": resolved_what_checked,
        "evidence":     evidence,   # Dict of key→value pairs of actual detected data
        "fix":          fix,        # Actionable remediation step
        "category":     resolved_category,
        # Legacy field kept so nothing existing breaks
        "message":      title,
    }
    if resource_type:
        item["resource_type"] = resource_type
    if resource_id:
        item["resource_id"] = resource_id
    return item


def evaluate(session, resources: dict) -> dict:
    # Short-circuit: nothing to evaluate if all resource lists are empty
    total = sum(len(v) for v in resources.values() if isinstance(v, list))
    if total == 0:
        return resources

    s3_client = session.client("s3") if session else None

    # Precompute active volume IDs for orphan snapshot check
    active_volume_ids = {v["id"] for v in resources.get("ebs_volumes", [])}

    ASSESSED_RESOURCE_TYPES = {
        "s3_buckets", "security_groups", "rds_instances", "ebs_volumes", "iam_roles",
        "ec2_instances", "elastic_ips", "snapshots", "ecr_repositories", "eks_clusters",
        "redshift_clusters", "aurora_clusters", "elasticache_clusters", "dynamodb_tables",
        "secrets", "sqs_queues", "sns_topics", "nat_gateways", "auto_scaling_groups",
        "ecs_clusters", "internet_gateways", "cloudwatch_alarms", "eventbridge_rules",
        "cloudformation_stacks", "lambda_functions", "load_balancers", "vpcs"
    }

    for r_type, items in resources.items():
        for r in items:
            raw = r.get("raw")
            if r_type not in ASSESSED_RESOURCE_TYPES:
                r["status"] = "NOT_ASSESSED"
                r["issues"] = []
                continue

            if not raw or not isinstance(raw, dict) or len(raw) == 0:
                r["status"] = "NOT_ASSESSED"
                r["issues"] = []
                continue

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
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Orphaned",
                    ))

            # ------------------------------------------------------------------
            # ECR Repositories
            # ------------------------------------------------------------------
            elif r_type == "ecr_repositories":
                repo_name = r["name"]
                mutability = raw.get("image_tag_mutability")
                scan_config = raw.get("image_scanning_configuration")
                if isinstance(scan_config, dict):
                    scan_on_push = scan_config.get("scanOnPush", False)
                else:
                    scan_on_push = False

                if mutability == "MUTABLE":
                    issues.append(_issue(
                        rule_id="ECR-001",
                        severity="WARNING",
                        title="ECR repository allows mutable image tags",
                        why="Mutable image tags allow existing container image tags to be overwritten, which can introduce unverified changes or vulnerabilities into production deployments.",
                        evidence={"Repository": repo_name, "ImageTagMutability": "MUTABLE"},
                        fix="Enable tag immutability: ECR Console → Select Repository → Edit settings → Turn on 'Tag immutability'.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

                if not scan_on_push:
                    issues.append(_issue(
                        rule_id="ECR-002",
                        severity="WARNING",
                        title="ECR automatic image vulnerability scanning disabled",
                        why="Automatic vulnerability scanning is disabled. Newly pushed images will not be assessed for known security flaws.",
                        evidence={"Repository": repo_name, "ScanOnPush": "False"},
                        fix="Enable scan on push: ECR Console → Select Repository → Edit settings → Turn on 'Scan on push'.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

            # ------------------------------------------------------------------
            # EKS Clusters
            # ------------------------------------------------------------------
            elif r_type == "eks_clusters":
                cluster_name = r["name"]
                vpc_config = raw.get("resources_vpc_config") or {}
                if vpc_config.get("endpointPublicAccess") is True and "0.0.0.0/0" in vpc_config.get("publicAccessCidrs", []):
                    issues.append(_issue(
                        rule_id="EKS-001",
                        severity="CRITICAL",
                        title="EKS API server endpoint is publicly accessible to all IPs",
                        why="Kubernetes API server endpoint is exposed to 0.0.0.0/0, allowing any host on the internet to attempt to connect and exploit potential vulnerabilities.",
                        evidence={"Cluster": cluster_name, "EndpointPublicAccess": "True", "PublicAccessCidrs": "0.0.0.0/0"},
                        fix="Restrict API server access: EKS Console → Select Cluster → Networking → Manage networking → Restrict public access CIDRs or disable public access.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

            # ------------------------------------------------------------------
            # Redshift Clusters
            # ------------------------------------------------------------------
            elif r_type == "redshift_clusters":
                cluster_id = r["id"]
                if raw.get("publicly_accessible") is True:
                    issues.append(_issue(
                        rule_id="RS-001",
                        severity="CRITICAL",
                        title="Redshift cluster is publicly accessible",
                        why="The data warehouse cluster is reachable directly from the public internet, exposing analytical data to external connection attempts.",
                        evidence={"Cluster": cluster_id, "PubliclyAccessible": "True"},
                        fix="Modify cluster network settings: disable 'Publicly accessible' and connect via private VPC subnets.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))
                if raw.get("encrypted") is False:
                    issues.append(_issue(
                        rule_id="RS-002",
                        severity="WARNING",
                        title="Redshift cluster storage is not encrypted",
                        why="Data warehouse storage is not encrypted at rest, which risks data exposure if physical storage media is accessed outside normal AWS controls.",
                        evidence={"Cluster": cluster_id, "Encrypted": "False"},
                        fix="Enable encryption on the Redshift cluster or create an encrypted snapshot copy and restore to an encrypted cluster.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

            # ------------------------------------------------------------------
            # Aurora DB Clusters
            # ------------------------------------------------------------------
            elif r_type == "aurora_clusters":
                cluster_id = r["id"]
                if raw.get("storage_encrypted") is False:
                    issues.append(_issue(
                        rule_id="AUR-001",
                        severity="WARNING",
                        title="Aurora cluster storage is not encrypted",
                        why="Aurora DB cluster storage volume is not encrypted at rest, creating compliance and data exposure risks.",
                        evidence={"Cluster": cluster_id, "StorageEncrypted": "False"},
                        fix="Take a snapshot of the Aurora cluster, copy it with KMS encryption enabled, and restore an encrypted cluster.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))
                if raw.get("deletion_protection") is False:
                    issues.append(_issue(
                        rule_id="AUR-002",
                        severity="WARNING",
                        title="Aurora cluster deletion protection is disabled",
                        why="Without deletion protection, the database cluster can be inadvertently deleted through the console, CLI, or automation.",
                        evidence={"Cluster": cluster_id, "DeletionProtection": "Disabled"},
                        fix="Enable deletion protection: RDS Console → Databases → Select Aurora Cluster → Modify → Check 'Enable deletion protection'.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Reliability",
                    ))

            # ------------------------------------------------------------------
            # ElastiCache Clusters
            # ------------------------------------------------------------------
            elif r_type == "elasticache_clusters":
                cluster_id = r["id"]
                if raw.get("at_rest_encryption_enabled") is False:
                    issues.append(_issue(
                        rule_id="EC-001",
                        severity="WARNING",
                        title="ElastiCache cluster encryption at rest is disabled",
                        why="In-memory cache data persisted to disk or backups is unencrypted.",
                        evidence={"CacheCluster": cluster_id, "AtRestEncryption": "Disabled"},
                        fix="Enable encryption at rest when creating replication groups or clusters.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))
                if raw.get("transit_encryption_enabled") is False:
                    issues.append(_issue(
                        rule_id="EC-002",
                        severity="WARNING",
                        title="ElastiCache cluster in-transit encryption is disabled",
                        why="Network traffic between clients and cache nodes is not encrypted with TLS, risking credential and data interception in transit.",
                        evidence={"CacheCluster": cluster_id, "TransitEncryption": "Disabled"},
                        fix="Enable in-transit encryption (TLS) on the replication group.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

            # ------------------------------------------------------------------
            # DynamoDB Tables
            # ------------------------------------------------------------------
            elif r_type == "dynamodb_tables":
                table_name = r["name"]
                sse_desc = raw.get("sse_description") or {}
                if not sse_desc or sse_desc.get("Status") != "ENABLED":
                    issues.append(_issue(
                        rule_id="DDB-001",
                        severity="WARNING",
                        title="DynamoDB table not encrypted with customer-managed KMS key",
                        why="Table relies on the default AWS-owned key instead of a customer-managed KMS key, preventing fine-grained access audits in CloudTrail.",
                        evidence={"Table": table_name, "SSEStatus": sse_desc.get("Status", "DEFAULT")},
                        fix="Update encryption: DynamoDB Console → Select Table → Additional settings → Encryption at rest → Manage KMS encryption.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

            # ------------------------------------------------------------------
            # Secrets Manager
            # ------------------------------------------------------------------
            elif r_type == "secrets":
                secret_name = r["name"]
                if raw.get("rotation_enabled") is False:
                    issues.append(_issue(
                        rule_id="SEC-001",
                        severity="WARNING",
                        title="Secrets Manager automatic rotation is disabled",
                        why="Static secrets that are not regularly rotated increase the exposure window if credentials become compromised.",
                        evidence={"Secret": secret_name, "RotationEnabled": "False"},
                        fix="Configure automatic rotation: Secrets Manager → Select Secret → Rotation configuration → Turn on automatic rotation.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))
                if not raw.get("kms_key_id"):
                    issues.append(_issue(
                        rule_id="SEC-002",
                        severity="WARNING",
                        title="Secret encrypted with default key rather than customer KMS key",
                        why="The default AWS managed key cannot be audited or shared across accounts using custom KMS key policies.",
                        evidence={"Secret": secret_name, "KmsKeyId": "Default/None"},
                        fix="Edit secret encryption: Secrets Manager → Select Secret → Edit encryption key → Specify a customer managed KMS key.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

            # ------------------------------------------------------------------
            # SQS Queues
            # ------------------------------------------------------------------
            elif r_type == "sqs_queues":
                queue_name = r["name"]
                if not raw.get("kms_master_key_id"):
                    issues.append(_issue(
                        rule_id="SQS-001",
                        severity="WARNING",
                        title="SQS queue server-side encryption disabled",
                        why="Queue messages stored in transit and at rest are not encrypted with a KMS master key.",
                        evidence={"Queue": queue_name, "KmsMasterKeyId": "None"},
                        fix="Enable encryption: SQS Console → Select Queue → Edit → Encryption → Enable SSE-KMS.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

            # ------------------------------------------------------------------
            # SNS Topics
            # ------------------------------------------------------------------
            elif r_type == "sns_topics":
                topic_name = r["name"]
                if not raw.get("kms_master_key_id"):
                    issues.append(_issue(
                        rule_id="SNS-001",
                        severity="WARNING",
                        title="SNS topic server-side encryption disabled",
                        why="Notification topic messages are not encrypted at rest with a KMS master key.",
                        evidence={"Topic": topic_name, "KmsMasterKeyId": "None"},
                        fix="Enable encryption: SNS Console → Select Topic → Edit → Encryption → Enable SSE with KMS.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

            # ------------------------------------------------------------------
            # NAT Gateways
            # ------------------------------------------------------------------
            elif r_type == "nat_gateways":
                nat_id = r["id"]
                state = str(raw.get("state", "")).lower()
                if state == "failed":
                    issues.append(_issue(
                        rule_id="NAT-001",
                        severity="WARNING",
                        title="NAT Gateway is in a failed state",
                        why="NAT Gateway has failed and cannot route outbound internet traffic from private subnets.",
                        evidence={"NatGateway": nat_id, "State": "failed"},
                        fix="Check VPC route tables and subnet configuration, recreate the NAT Gateway, and update routing.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Reliability",
                    ))
                elif state == "available":
                    issues.append(_issue(
                        rule_id="NAT-002",
                        severity="WARNING",
                        title="Active NAT Gateway configuration generates continuous hourly charges",
                        why="NAT Gateways incur hourly availability charges and data processing fees while provisioned. Verify whether private subnets actively require internet egress.",
                        evidence={"NatGateway": nat_id, "State": "available", "SubnetId": str(raw.get("subnet_id"))},
                        fix="Audit private subnet route tables. If instances do not require outbound internet access, delete the NAT Gateway to avoid unnecessary charges.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Cost Risk",
                    ))

            # ------------------------------------------------------------------
            # Auto Scaling Groups
            # ------------------------------------------------------------------
            elif r_type == "auto_scaling_groups":
                asg_name = r["name"]
                desired = raw.get("desired_capacity", 0)
                min_size = raw.get("min_size", 0)
                if desired == 0 and min_size == 0:
                    issues.append(_issue(
                        rule_id="ASG-001",
                        severity="ORPHANED",
                        title="Auto Scaling Group has zero active capacity",
                        why="Auto Scaling Group has both desired capacity and minimum size set to 0. It is running no compute instances and may be abandoned.",
                        evidence={"AutoScalingGroup": asg_name, "DesiredCapacity": "0", "MinSize": "0"},
                        fix="If this scaling group is obsolete, delete it to keep your AWS account clean.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Orphaned",
                    ))

            # ------------------------------------------------------------------
            # ECS Clusters
            # ------------------------------------------------------------------
            elif r_type == "ecs_clusters":
                cluster_name = r["name"]
                registered = raw.get("registered_container_instances_count", 0)
                active = raw.get("active_services_count", 0)
                if registered == 0 and active == 0:
                    issues.append(_issue(
                        rule_id="ECS-001",
                        severity="ORPHANED",
                        title="ECS cluster has no registered instances or active services",
                        why="The cluster has 0 EC2/Fargate instances and 0 running services, serving no active workloads.",
                        evidence={"Cluster": cluster_name, "RegisteredInstances": "0", "ActiveServices": "0"},
                        fix="If the cluster is no longer needed, delete it: ECS Console → Select Cluster → Delete Cluster.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Orphaned",
                    ))

            # ------------------------------------------------------------------
            # Internet Gateways
            # ------------------------------------------------------------------
            elif r_type == "internet_gateways":
                igw_id = r["id"]
                attachments = raw.get("attachments", [])
                if len(attachments) == 0:
                    issues.append(_issue(
                        rule_id="IGW-001",
                        severity="ORPHANED",
                        title="Internet Gateway is not attached to any VPC",
                        why="The Internet Gateway exists independently without routing traffic for any VPC, representing an abandoned networking resource.",
                        evidence={"InternetGateway": igw_id, "Attachments": "0"},
                        fix="Attach the gateway to a VPC if needed, or delete it from the VPC console.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Orphaned",
                    ))

            # ------------------------------------------------------------------
            # CloudWatch Alarms
            # ------------------------------------------------------------------
            elif r_type == "cloudwatch_alarms":
                alarm_name = r["name"]
                actions_enabled = raw.get("actions_enabled", True)
                state_value = raw.get("state_value")
                if actions_enabled is False:
                    issues.append(_issue(
                        rule_id="CW-001",
                        severity="WARNING",
                        title="CloudWatch alarm actions are disabled",
                        why="The alarm has actions disabled and will not send notifications or execute automated remediation when triggered.",
                        evidence={"Alarm": alarm_name, "ActionsEnabled": "False"},
                        fix="Enable alarm actions: CloudWatch Console → Alarms → Select Alarm → Actions → Enable actions.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Reliability",
                    ))
                if state_value == "INSUFFICIENT_DATA":
                    issues.append(_issue(
                        rule_id="CW-002",
                        severity="WARNING",
                        title="CloudWatch alarm has insufficient metric data",
                        why="Alarm is in INSUFFICIENT_DATA state, which typically indicates the monitored resource was deleted or metric publishing stopped.",
                        evidence={"Alarm": alarm_name, "StateValue": "INSUFFICIENT_DATA"},
                        fix="Verify if the underlying resource exists. If the monitored workload was decommissioned, delete the alarm.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Reliability",
                    ))

            # ------------------------------------------------------------------
            # EventBridge Rules
            # ------------------------------------------------------------------
            elif r_type == "eventbridge_rules":
                rule_name = r["name"]
                state = raw.get("state")
                if state == "DISABLED":
                    issues.append(_issue(
                        rule_id="EV-001",
                        severity="ORPHANED",
                        title="EventBridge rule is disabled",
                        why="Rule is in DISABLED state and does not process events or trigger scheduled targets.",
                        evidence={"Rule": rule_name, "State": "DISABLED"},
                        fix="Re-enable the rule if automation is active, or delete it to remove obsolete event routes.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Orphaned",
                    ))

            # ------------------------------------------------------------------
            # CloudFormation Stacks
            # ------------------------------------------------------------------
            elif r_type == "cloudformation_stacks":
                stack_name = r["name"]
                stack_status = raw.get("stack_status", "")
                term_protection = raw.get("enable_termination_protection", False)
                if stack_status in ["ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "DELETE_FAILED", "CREATE_FAILED"]:
                    issues.append(_issue(
                        rule_id="CFN-001",
                        severity="ORPHANED",
                        title="CloudFormation stack is in a failed or rollback state",
                        why=f"Stack is in '{stack_status}' state and may retain orphaned cloud resources from failed deployments.",
                        evidence={"Stack": stack_name, "StackStatus": stack_status},
                        fix="Inspect stack events for root cause errors, delete the failed stack, or trigger a clean rollback.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Orphaned",
                    ))
                elif term_protection is False:
                    issues.append(_issue(
                        rule_id="CFN-002",
                        severity="WARNING",
                        title="CloudFormation stack termination protection is disabled",
                        why="Without termination protection, the entire stack and all its managed resources can be deleted with a single command.",
                        evidence={"Stack": stack_name, "TerminationProtection": "Disabled"},
                        fix="Enable termination protection: CloudFormation → Select Stack → Stack actions → Edit termination protection.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Reliability",
                    ))

            # ------------------------------------------------------------------
            # Lambda Functions
            # ------------------------------------------------------------------
            elif r_type == "lambda_functions":
                fn_name = r["name"]
                last_mod = raw.get("last_modified")
                if last_mod:
                    try:
                        import datetime
                        if "+" in last_mod:
                            time_part = last_mod.split("+")[0]
                            dt = datetime.datetime.strptime(time_part, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)
                        else:
                            dt = datetime.datetime.strptime(last_mod, "%Y-%m-%dT%H:%M:%S.%f%z")
                        age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
                        if age_days > 90:
                            issues.append(_issue(
                                rule_id="LAM-001",
                                severity="WARNING",
                                title="Lambda function has not been modified in over 90 days",
                                why="Serverless functions left unmaintained may use older runtimes or contain unpatched third-party library dependencies.",
                                evidence={"Function": fn_name, "LastModified": str(last_mod), "DaysSinceModified": str(age_days)},
                                fix="Verify if the function is still actively used. Update its runtime and dependencies, or delete obsolete functions.",
                                resource_type=r["type"],
                                resource_id=r["id"],
                                category="Hygiene",
                            ))
                    except Exception:
                        pass

            # ------------------------------------------------------------------
            # Load Balancers
            # ------------------------------------------------------------------
            elif r_type == "load_balancers":
                lb_name = r["name"]
                scheme = raw.get("scheme")
                if scheme == "internet-facing":
                    issues.append(_issue(
                        rule_id="ELB-001",
                        severity="WARNING",
                        title="Load balancer is publicly accessible from the internet",
                        why="Load balancer scheme is configured as internet-facing with a public DNS name.",
                        evidence={"LoadBalancer": lb_name, "Scheme": "internet-facing"},
                        fix="Verify whether public exposure is intended. Internal backend services should be deployed with 'internal' scheme.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
                    ))

            # ------------------------------------------------------------------
            # VPCs
            # ------------------------------------------------------------------
            elif r_type == "vpcs":
                vpc_id = r["id"]
                if raw.get("is_default") is True:
                    issues.append(_issue(
                        rule_id="VPC-001",
                        severity="WARNING",
                        title="Default VPC is present and active",
                        why="Default VPCs have public subnets by default and lack customized network segmentation suitable for production workloads.",
                        evidence={"VpcId": vpc_id, "IsDefault": "True", "CidrBlock": str(raw.get("cidr_block", "unknown"))},
                        fix="Deploy production resources in custom VPCs with private subnets, security groups, and explicit routing.",
                        resource_type=r["type"],
                        resource_id=r["id"],
                        category="Security",
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
