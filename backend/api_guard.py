"""Authoritative AWS API operation allowlist and client-layer enforcement.

Every AWS API call executed by AWS Clarity's local scanner (`doctor` and `scan`)
must be declared in `ALLOWED_AWS_OPERATIONS` below. Enforcement happens at the
boto3/botocore client layer via BOTH:
  1. A botocore `before-call.*.*` event hook attached to every real client.
  2. A `GuardedClient` proxy wrapper that blocks unlisted method and paginator
     invocations before execution (covering both real and mocked sessions).

Enforcement NEVER relies on action-name prefixes ("Describe"/"List"/"Get"). Any
unlisted operation—read or write—raises `DisallowedAWSOperationError`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class DisallowedAWSOperationError(PermissionError):
    """Raised when code attempts an AWS API operation outside the explicit allowlist."""


@dataclass(frozen=True)
class AllowedOperation:
    service: str
    operation: str          # Botocore PascalCase operation name (e.g. DescribeInstances)
    method_name: str        # Boto3 snake_case client method (e.g. describe_instances)
    collector: str          # Module/function invoking this operation
    iam_action: str         # Exact IAM permission action (e.g. ec2:DescribeInstances)
    purpose: str            # Plain-English purpose
    data_sensitivity: str   # What sensitivity class of metadata is returned
    possible_charges: str   # AWS API request charge profile
    optional_s3: bool = False


# Single source of truth for all 34 scan/doctor IAM permissions (28 default + 6 optional S3).
# Order matches `build_policy_document()` and `frontend/src/utils/constants.js` 1:1.
ALLOWED_AWS_OPERATIONS: tuple[AllowedOperation, ...] = (
    AllowedOperation(
        service="sts",
        operation="GetCallerIdentity",
        method_name="get_caller_identity",
        collector="local_engine.verify_identity",
        iam_action="sts:GetCallerIdentity",
        purpose="Verify active AWS account ID and caller ARN before scanning",
        data_sensitivity="Low (account ID and caller ARN only; never credentials)",
        possible_charges="Free AWS STS call ($0)",
    ),
    AllowedOperation(
        service="ec2",
        operation="DescribeRegions",
        method_name="describe_regions",
        collector="lambda_handler.discover_enabled_regions",
        iam_action="ec2:DescribeRegions",
        purpose="List enabled AWS regions in the account",
        data_sensitivity="Low (region names and opt-in status)",
        possible_charges="Free EC2 control-plane call ($0)",
    ),
    AllowedOperation(
        service="ec2",
        operation="DescribeInstances",
        method_name="describe_instances",
        collector="scanner.ec2.scan / CORE_PERMISSIONS",
        iam_action="ec2:DescribeInstances",
        purpose="Inspect EC2 instance state, IMDSv2 enforcement, and VPC/SG links",
        data_sensitivity="Medium (instance IDs, VPC/subnet IDs, public IP; tags/private IP discarded)",
        possible_charges="Free EC2 control-plane call ($0)",
    ),
    AllowedOperation(
        service="ec2",
        operation="DescribeAddresses",
        method_name="describe_addresses",
        collector="scanner.elastic_ip.scan",
        iam_action="ec2:DescribeAddresses",
        purpose="Detect unassociated Elastic IPs incurring hourly IPv4 charges",
        data_sensitivity="Medium (public IPv4 addresses and association IDs; tags discarded)",
        possible_charges="Free EC2 control-plane call ($0)",
    ),
    AllowedOperation(
        service="ec2",
        operation="DescribeSecurityGroups",
        method_name="describe_security_groups",
        collector="scanner.security_group.scan",
        iam_action="ec2:DescribeSecurityGroups",
        purpose="Detect unrestricted inbound firewall rules (0.0.0.0/0, ::/0)",
        data_sensitivity="Medium (ports, protocols, CIDRs; free-text descriptions discarded)",
        possible_charges="Free EC2 control-plane call ($0)",
    ),
    AllowedOperation(
        service="ec2",
        operation="DescribeVpcs",
        method_name="describe_vpcs",
        collector="scanner.vpcs.scan / CORE_PERMISSIONS",
        iam_action="ec2:DescribeVpcs",
        purpose="Identify default VPCs hosting active public workloads",
        data_sensitivity="Low (VPC IDs, CIDR blocks, default flag; tags discarded)",
        possible_charges="Free EC2 control-plane call ($0)",
    ),
    AllowedOperation(
        service="ec2",
        operation="DescribeInternetGateways",
        method_name="describe_internet_gateways",
        collector="scanner.internet_gateways.scan",
        iam_action="ec2:DescribeInternetGateways",
        purpose="Detect detached Internet Gateways",
        data_sensitivity="Low (IGW IDs and VPC attachment state; tags discarded)",
        possible_charges="Free EC2 control-plane call ($0)",
    ),
    AllowedOperation(
        service="ec2",
        operation="DescribeNatGateways",
        method_name="describe_nat_gateways",
        collector="scanner.nat_gateways.scan",
        iam_action="ec2:DescribeNatGateways",
        purpose="Detect failed NAT Gateways and surface ongoing NAT cost review",
        data_sensitivity="Low-Medium (NAT IDs, state, VPC/subnet, public IP; tags discarded)",
        possible_charges="Free EC2 control-plane call ($0)",
    ),
    AllowedOperation(
        service="ec2",
        operation="DescribeVolumes",
        method_name="describe_volumes",
        collector="scanner.ebs.scan / CORE_PERMISSIONS",
        iam_action="ec2:DescribeVolumes",
        purpose="Detect unencrypted and unattached EBS volumes",
        data_sensitivity="Low (volume IDs, size, state, encryption flag; tags discarded)",
        possible_charges="Free EC2 control-plane call ($0)",
    ),
    AllowedOperation(
        service="ec2",
        operation="DescribeSnapshots",
        method_name="describe_snapshots",
        collector="scanner.snapshots.scan",
        iam_action="ec2:DescribeSnapshots",
        purpose="Review self-owned snapshots whose source volume no longer exists",
        data_sensitivity="Low (snapshot ID, source volume ID, size, encrypted flag; descriptions/tags discarded)",
        possible_charges="Free EC2 control-plane call ($0)",
    ),
    # Optional S3 metadata operations (disabled by default; require explicit consent)
    AllowedOperation(
        service="s3",
        operation="ListBuckets",
        method_name="list_buckets",
        collector="scanner.s3.scan / CORE_PERMISSIONS",
        iam_action="s3:ListAllMyBuckets",
        purpose="List bucket names in the account when S3 checks are opted in",
        data_sensitivity="Low (bucket names and creation dates only; never lists objects)",
        possible_charges="S3 LIST request ($0.005 / 1,000 requests outside 12-mo S3 Free Tier)",
        optional_s3=True,
    ),
    AllowedOperation(
        service="s3",
        operation="GetBucketLocation",
        method_name="get_bucket_location",
        collector="scanner.s3._inspect_bucket",
        iam_action="s3:GetBucketLocation",
        purpose="Determine each bucket's AWS region",
        data_sensitivity="Low (region constraint only)",
        possible_charges="S3 GET request ($0.0004 / 1,000 requests outside 12-mo S3 Free Tier)",
        optional_s3=True,
    ),
    AllowedOperation(
        service="s3",
        operation="GetBucketPolicyStatus",
        method_name="get_bucket_policy_status",
        collector="scanner.misconfig.evaluate",
        iam_action="s3:GetBucketPolicyStatus",
        purpose="Check IsPublic boolean for bucket policy (never reads raw policy JSON)",
        data_sensitivity="Low (boolean IsPublic only)",
        possible_charges="S3 GET request ($0.0004 / 1,000 requests outside 12-mo S3 Free Tier)",
        optional_s3=True,
    ),
    AllowedOperation(
        service="s3",
        operation="GetBucketAcl",
        method_name="get_bucket_acl",
        collector="scanner.misconfig.evaluate",
        iam_action="s3:GetBucketAcl",
        purpose="Check for AllUsers or AuthenticatedUsers public ACL grants",
        data_sensitivity="Low (public grantee URI check only; canonical IDs not retained)",
        possible_charges="S3 GET request ($0.0004 / 1,000 requests outside 12-mo S3 Free Tier)",
        optional_s3=True,
    ),
    AllowedOperation(
        service="s3",
        operation="GetBucketEncryption",
        method_name="get_bucket_encryption",
        collector="scanner.misconfig.evaluate",
        iam_action="s3:GetEncryptionConfiguration",
        purpose="Verify default bucket encryption metadata is readable (respects SSE-S3)",
        data_sensitivity="Low (readability check only; KMS key ARNs not retained)",
        possible_charges="S3 GET request ($0.0004 / 1,000 requests outside 12-mo S3 Free Tier)",
        optional_s3=True,
    ),
    AllowedOperation(
        service="s3",
        operation="GetPublicAccessBlock",
        method_name="get_public_access_block",
        collector="scanner.misconfig.evaluate",
        iam_action="s3:GetBucketPublicAccessBlock",
        purpose="Check the four S3 Block Public Access boolean guardrails",
        data_sensitivity="Low (4 boolean flags only)",
        possible_charges="S3 GET request ($0.0004 / 1,000 requests outside 12-mo S3 Free Tier)",
        optional_s3=True,
    ),
    # IAM
    AllowedOperation(
        service="iam",
        operation="ListRoles",
        method_name="list_roles",
        collector="scanner.iam.scan_roles / CORE_PERMISSIONS",
        iam_action="iam:ListRoles",
        purpose="List IAM roles and trust policy structure",
        data_sensitivity="Medium (role names, ARNs, trust principal accounts; condition values/descriptions/tags discarded)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    AllowedOperation(
        service="iam",
        operation="ListRolePolicies",
        method_name="list_role_policies",
        collector="scanner.iam._inspect_role",
        iam_action="iam:ListRolePolicies",
        purpose="List inline policy names attached to each IAM role",
        data_sensitivity="Low (policy names only)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    AllowedOperation(
        service="iam",
        operation="GetRolePolicy",
        method_name="get_role_policy",
        collector="scanner.iam._inspect_role",
        iam_action="iam:GetRolePolicy",
        purpose="Evaluate inline role policy statements for wildcard/unscoped admin rules",
        data_sensitivity="Medium (minimized immediately: condition values & scoped ARNs discarded; full docs pruned from output)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    AllowedOperation(
        service="iam",
        operation="ListAttachedRolePolicies",
        method_name="list_attached_role_policies",
        collector="scanner.iam._inspect_role",
        iam_action="iam:ListAttachedRolePolicies",
        purpose="Detect AdministratorAccess, IAMFullAccess, and PowerUserAccess on roles",
        data_sensitivity="Low (managed policy names and ARNs only)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    AllowedOperation(
        service="iam",
        operation="ListUsers",
        method_name="list_users",
        collector="scanner.iam.scan_users",
        iam_action="iam:ListUsers",
        purpose="List IAM users and console PasswordLastUsed metadata",
        data_sensitivity="Medium (usernames, ARNs, PasswordLastUsed; never reads passwords/tags)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    AllowedOperation(
        service="iam",
        operation="ListMFADevices",
        method_name="list_mfa_devices",
        collector="scanner.iam._inspect_user",
        iam_action="iam:ListMFADevices",
        purpose="Count MFA devices per IAM user (IAM-009)",
        data_sensitivity="Low (device count only; MFA serial numbers discarded)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    AllowedOperation(
        service="iam",
        operation="ListAccessKeys",
        method_name="list_access_keys",
        collector="scanner.iam._inspect_user",
        iam_action="iam:ListAccessKeys",
        purpose="Check active access key age >90 days (IAM-010; never returns secrets)",
        data_sensitivity="Medium (AccessKeyId prefix/ID, status, create date; AWS never returns SecretAccessKey here)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    AllowedOperation(
        service="iam",
        operation="ListAttachedUserPolicies",
        method_name="list_attached_user_policies",
        collector="scanner.iam._inspect_user",
        iam_action="iam:ListAttachedUserPolicies",
        purpose="Detect AdministratorAccess attached directly to IAM users",
        data_sensitivity="Low (managed policy names and ARNs only)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    AllowedOperation(
        service="iam",
        operation="ListUserPolicies",
        method_name="list_user_policies",
        collector="scanner.iam._inspect_user",
        iam_action="iam:ListUserPolicies",
        purpose="List inline policy names attached directly to IAM users",
        data_sensitivity="Low (policy names only)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    AllowedOperation(
        service="iam",
        operation="GetUserPolicy",
        method_name="get_user_policy",
        collector="scanner.iam._inspect_user",
        iam_action="iam:GetUserPolicy",
        purpose="Detect inline Action:* on Resource:* attached directly to IAM users",
        data_sensitivity="Medium (minimized immediately: condition values & scoped ARNs discarded; full docs pruned from output)",
        possible_charges="Free AWS IAM call ($0)",
    ),
    # Lambda
    AllowedOperation(
        service="lambda",
        operation="ListFunctions",
        method_name="list_functions",
        collector="scanner.lambda_functions.scan / CORE_PERMISSIONS",
        iam_action="lambda:ListFunctions",
        purpose="Check Lambda runtimes and last-modified timestamps",
        data_sensitivity="Low-Medium (runtime, memory, timeout, VPC links; Environment.Variables values & descriptions discarded immediately)",
        possible_charges="Free Lambda control-plane call ($0)",
    ),
    # RDS
    AllowedOperation(
        service="rds",
        operation="DescribeDBInstances",
        method_name="describe_db_instances",
        collector="scanner.rds.scan / CORE_PERMISSIONS",
        iam_action="rds:DescribeDBInstances",
        purpose="Check public access, encryption, deletion protection, and backup retention",
        data_sensitivity="Medium (DB identifier, engine, flags, VPC/SGs; Endpoint hostname, MasterUsername, KMS keys & tags discarded)",
        possible_charges="Free RDS control-plane call ($0)",
    ),
    # DynamoDB
    AllowedOperation(
        service="dynamodb",
        operation="ListTables",
        method_name="list_tables",
        collector="scanner.dynamodb_tables.scan / CORE_PERMISSIONS",
        iam_action="dynamodb:ListTables",
        purpose="List DynamoDB table names per region",
        data_sensitivity="Low (table names only; never reads items)",
        possible_charges="Free DynamoDB control-plane call ($0)",
    ),
    AllowedOperation(
        service="dynamodb",
        operation="DescribeTable",
        method_name="describe_table",
        collector="scanner.dynamodb_tables._inspect_table",
        iam_action="dynamodb:DescribeTable",
        purpose="Inspect DynamoDB encryption status, billing mode, and approximate item count",
        data_sensitivity="Low (table metadata & SSE Status/Type only; KMS key ARN discarded; never reads items)",
        possible_charges="Free DynamoDB control-plane call ($0)",
    ),
    # CloudWatch & Logs
    AllowedOperation(
        service="cloudwatch",
        operation="DescribeAlarms",
        method_name="describe_alarms",
        collector="scanner.cloudwatch.scan_alarms / CORE_PERMISSIONS",
        iam_action="cloudwatch:DescribeAlarms",
        purpose="Check alarm ActionsEnabled flag and INSUFFICIENT_DATA state",
        data_sensitivity="Low (alarm name, state, actions_enabled, action count; descriptions, dimensions & action ARNs discarded)",
        possible_charges="Free CloudWatch control-plane call ($0)",
    ),
    AllowedOperation(
        service="logs",
        operation="DescribeLogGroups",
        method_name="describe_log_groups",
        collector="scanner.cloudwatch.scan_log_groups",
        iam_action="logs:DescribeLogGroups",
        purpose="Check CloudWatch Log Group retentionInDays (Never Expire) and stored size",
        data_sensitivity="Low (log group name, retention, bytes, has_kms_key boolean; KMS key ARN discarded; never reads log events)",
        possible_charges="Free CloudWatch Logs control-plane call ($0)",
    ),
    # CloudTrail
    AllowedOperation(
        service="cloudtrail",
        operation="DescribeTrails",
        method_name="describe_trails",
        collector="scanner.cloudtrail.scan / CORE_PERMISSIONS",
        iam_action="cloudtrail:DescribeTrails",
        purpose="Inspect trail home region, multi-region coverage, and log file validation",
        data_sensitivity="Low (trail name/ARN, S3 destination bucket name, booleans; KMS key ARN discarded)",
        possible_charges="Free CloudTrail control-plane call ($0)",
    ),
    AllowedOperation(
        service="cloudtrail",
        operation="GetTrailStatus",
        method_name="get_trail_status",
        collector="scanner.cloudtrail.scan",
        iam_action="cloudtrail:GetTrailStatus",
        purpose="Verify IsLogging boolean for each CloudTrail trail",
        data_sensitivity="Low (IsLogging & has_delivery_error booleans only; raw error text discarded)",
        possible_charges="Free CloudTrail control-plane call ($0)",
    ),
)

# Separate explicit allowance for customer-requested local `--role-arn` assumption ONLY.
# Never included in scanner clients or the target read-only role's IAM policy.
ROLE_ASSUMPTION_OPERATION = AllowedOperation(
    service="sts",
    operation="AssumeRole",
    method_name="assume_role",
    collector="local_engine.create_local_session",
    iam_action="sts:AssumeRole",
    purpose="Optional local role assumption when the user explicitly supplies --role-arn",
    data_sensitivity="Temporary STS credentials kept in process memory only; never printed or written",
    possible_charges="Free AWS STS call ($0)",
)


def get_allowed_iam_actions(include_s3: bool = True) -> list[str]:
    """Return the exact ordered IAM Action list derived from `ALLOWED_AWS_OPERATIONS`."""
    return [
        entry.iam_action
        for entry in ALLOWED_AWS_OPERATIONS
        if include_s3 or not entry.optional_s3
    ]


def get_allowed_operations_map(include_s3: bool = True) -> dict[str, set[str]]:
    """Map service_name -> set of allowed botocore PascalCase operation names."""
    mapping: dict[str, set[str]] = {}
    for entry in ALLOWED_AWS_OPERATIONS:
        if not include_s3 and entry.optional_s3:
            continue
        mapping.setdefault(entry.service, set()).add(entry.operation)
    return mapping


def get_allowed_methods_map(include_s3: bool = True) -> dict[str, set[str]]:
    """Map service_name -> set of allowed boto3 snake_case method/paginator names."""
    mapping: dict[str, set[str]] = {}
    for entry in ALLOWED_AWS_OPERATIONS:
        if not include_s3 and entry.optional_s3:
            continue
        mapping.setdefault(entry.service, set()).add(entry.method_name)
    return mapping


def _normalize_service_name(service_name: str) -> str:
    lowered = str(service_name or "").strip().lower()
    if lowered == "monitoring":
        return "cloudwatch"
    return lowered


class GuardedClient:
    """Client proxy enforcing the explicit AWS operation allowlist before any call."""

    _SAFE_PASSTHROUGH_ATTRS = frozenset({
        "meta",
        "exceptions",
        "can_paginate",
        "close",
    })

    def __init__(
        self,
        raw_client: Any,
        service_name: str,
        include_s3: bool = True,
        allow_assume_role: bool = False,
    ):
        self._raw_client = raw_client
        self._service_name = _normalize_service_name(service_name)
        self._allowed_ops = set(get_allowed_operations_map(include_s3=include_s3).get(self._service_name, set()))
        self._allowed_methods = set(get_allowed_methods_map(include_s3=include_s3).get(self._service_name, set()))
        if allow_assume_role and self._service_name == "sts":
            self._allowed_ops.add(ROLE_ASSUMPTION_OPERATION.operation)
            self._allowed_methods.add(ROLE_ASSUMPTION_OPERATION.method_name)
        self._attach_botocore_hook()

    def _attach_botocore_hook(self) -> None:
        meta = getattr(self._raw_client, "meta", None)
        events = getattr(meta, "events", None)
        register = getattr(events, "register", None)
        if not callable(register):
            return
        # Avoid registering duplicate hooks if the same underlying client is re-wrapped
        if getattr(self._raw_client, "_aws_clarity_guard_attached", False):
            return

        service_name = self._service_name
        allowed_ops = self._allowed_ops

        def _enforce_before_call(model=None, **_kwargs):
            op_name = getattr(model, "name", None)
            if op_name not in allowed_ops:
                raise DisallowedAWSOperationError(
                    f"Blocked unlisted AWS API operation: {service_name}.{op_name}. "
                    "AWS Clarity only permits explicitly allowlisted read-only operations."
                )

        try:
            register(
                "before-call.*.*",
                _enforce_before_call,
                unique_id=f"aws-clarity-guard-{id(self._raw_client)}",
            )
            setattr(self._raw_client, "_aws_clarity_guard_attached", True)
        except Exception:
            # Mock clients expose MagicMock for meta.events.register; method-level guard still enforces.
            pass

    def get_paginator(self, operation_name: str):
        if operation_name not in self._allowed_methods:
            raise DisallowedAWSOperationError(
                f"Blocked unlisted AWS paginator operation: {self._service_name}.{operation_name}. "
                "AWS Clarity only permits explicitly allowlisted read-only operations."
            )
        return self._raw_client.get_paginator(operation_name)

    def __getattr__(self, name: str):
        if name.startswith("_") or name in self._SAFE_PASSTHROUGH_ATTRS:
            return getattr(self._raw_client, name)
        if name not in self._allowed_methods:
            raise DisallowedAWSOperationError(
                f"Blocked unlisted AWS API method: {self._service_name}.{name}. "
                "AWS Clarity only permits explicitly allowlisted read-only operations."
            )
        return getattr(self._raw_client, name)


def wrap_client_with_guard(
    raw_client: Any,
    service_name: str,
    include_s3: bool = True,
    allow_assume_role: bool = False,
) -> GuardedClient:
    """Wrap any boto3 or mock client with strict allowlist enforcement."""
    if isinstance(raw_client, GuardedClient):
        return raw_client
    return GuardedClient(
        raw_client=raw_client,
        service_name=service_name,
        include_s3=include_s3,
        allow_assume_role=allow_assume_role,
    )
