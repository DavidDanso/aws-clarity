"""Local-first AWS Clarity scanning engine.

Reuses the exact existing 10-service collectors (`scanner/*`) and deterministic
rule engine (`scanner/misconfig.py`) directly on the customer's workstation
using the standard AWS SDK credential provider chain (AWS CLI profiles,
IAM Identity Center / SSO, environment credentials, or a customer-owned role).

Privacy, safety & cost guarantees:
- Communicates ONLY with official AWS service endpoints via boto3/botocore.
- Enforces an explicit client-layer AWS API operation allowlist (`api_guard.py`).
- Refuses AWS account root credentials unless `--allow-root` is explicitly passed.
- Never sends credentials, metadata, or reports to AWS Clarity servers.
- Never prints or writes AWS access keys, secret keys, or session tokens.
- Skips S3 API checks by default (`SKIPPED_OPTIONAL`) because AWS S3 bills
  LIST/GET API requests outside the 12-month S3 Free Tier; requires explicit
  customer opt-in (`include_s3_checks=True` and `confirm_s3_request_costs=True`).
"""

import concurrent.futures
import datetime
import re
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound, TokenRetrievalError

from api_guard import (
    ALLOWED_AWS_OPERATIONS,
    get_allowed_iam_actions,
    wrap_client_with_guard,
)
from exceptions import AssumeRoleError, InvalidRoleARNError, RootIdentityBlockedError, ScannerError
from lambda_handler import (
    CORE_PERMISSIONS,
    OUT_OF_SCOPE_DISCLOSURES,
    SCANNER_METADATA,
    _collect_assessment_errors,
    _deduplicate_resources,
    _get_regional_scanners,
    _scan_region_batch_local,
    _scanner_status_entry,
    discover_enabled_regions,
)
from scanner import iam, s3
from scanner.misconfig import SERVICE_COVERAGE_MATRIX, evaluate, get_rules_catalog
from utils import (
    CachedSession,
    SCAN_BOTO_CONFIG,
    redact_credential_strings,
    validate_external_id,
    validate_role_arn,
)

# Workstation-friendly timeouts & pool size (avoids false timeouts on home/office broadband)
LOCAL_BOTO_CONFIG = Config(
    connect_timeout=4.0,
    read_timeout=12.0,
    max_pool_connections=32,
    retries={"max_attempts": 2, "mode": "standard"},
)

REPORT_SCHEMA_VERSION = "aws-clarity-report/v1"
CLI_VERSION = "1.1.0"

# Derived directly from `api_guard.ALLOWED_AWS_OPERATIONS` so runtime guard & IAM policy never drift.
DEFAULT_ZERO_COST_IAM_ACTIONS = get_allowed_iam_actions(include_s3=False)
OPTIONAL_S3_IAM_ACTIONS = [
    entry.iam_action for entry in ALLOWED_AWS_OPERATIONS if entry.optional_s3
]

S3_OPTIONAL_COST_NOTICE = (
    "Optional S3 checks call 1 s3:ListAllMyBuckets (LIST) plus 5 GetBucket* (GET) "
    "requests per bucket. Outside an account's 12-month S3 Free Tier (2,000 LIST / "
    "20,000 GET requests/mo), AWS S3 standard list pricing is $0.005 per 1,000 LIST "
    "requests and $0.0004 per 1,000 GET requests (e.g., ~$0.00004 for 20 buckets). "
    "No s3:ListBucket or s3:GetObject calls are ever made."
)

_ROOT_ARN_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:root$")
_ACCOUNT_IN_ARN_RE = re.compile(r"(arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:)(\d{12})(:)")
_IDENTITY_NAME_RE = re.compile(
    r"^arn:aws[a-z-]*:(?:iam|sts)::\d{12}:(?:user|role|assumed-role|federated-user)/(.+)$"
)


def mask_account_id(account_id: str | None) -> str:
    """Mask a 12-digit AWS account ID for safer terminal display (e.g. ********9012)."""
    raw = str(account_id or "").strip()
    if len(raw) == 12 and raw.isdigit():
        return f"********{raw[-4:]}"
    if len(raw) > 4:
        return f"{'*' * (len(raw) - 4)}{raw[-4:]}"
    return raw or "unknown"


def mask_caller_arn(caller_arn: str | None) -> str:
    """Mask the 12-digit AWS account ID inside a caller ARN."""
    raw = str(caller_arn or "").strip()
    if not raw:
        return "unknown"
    return _ACCOUNT_IN_ARN_RE.sub(lambda m: f"{m.group(1)}********{m.group(2)[-4:]}{m.group(3)}", raw)


def is_root_arn(caller_arn: str | None) -> bool:
    """Return True strictly when sts:GetCallerIdentity Arn is the AWS account root user."""
    return bool(_ROOT_ARN_RE.match(str(caller_arn or "").strip()))


def is_likely_admin_name_heuristic(caller_arn: str | None) -> bool:
    """NAME HEURISTIC ONLY: checks whether the user/role/assumed-role name contains 'admin'.

    Makes zero extra IAM or AWS API calls. Never determines effective permissions,
    and never assumes any non-matching role name (including 'ReadOnly') is actually read-only.
    """
    raw = str(caller_arn or "").strip()
    match = _IDENTITY_NAME_RE.match(raw)
    if not match:
        return False
    identity_tail = match.group(1)
    # Check user name, role path/name, or assumed-role name (exclude session name after second slash if assumed-role)
    parts = identity_tail.split("/")
    if ":assumed-role/" in raw and len(parts) >= 2:
        name_to_check = parts[0]
    else:
        name_to_check = identity_tail
    return "admin" in name_to_check.lower()


def format_root_refusal_message(caller_arn: str) -> str:
    return (
        f"Refused to run with AWS account root credentials ({mask_caller_arn(caller_arn)}).\n"
        "  Why: The AWS account root user has unrestricted control over your entire account and billing.\n"
        "  AWS best practice is to never use root credentials for routine tools or assessments.\n"
        "  Recommended: Sign in with a dedicated read-only IAM role or IAM Identity Center (SSO) profile.\n"
        "    Inspect exact read-only permissions : aws-clarity policy --zero-cost-only\n"
        "    Least-privilege CloudFormation role : infra/aws-clarity-readonly-role.yaml\n"
        "  If you understand the risk and explicitly choose to proceed anyway, pass --allow-root."
    )


def format_admin_heuristic_warning(caller_arn: str) -> str:
    return (
        f"WARNING (name heuristic only): Your caller ARN ({mask_caller_arn(caller_arn)}) includes 'admin' in its name.\n"
        "  Recommended: Use a dedicated read-only IAM role instead of a high-privilege identity.\n"
        "    Inspect exact read-only permissions : aws-clarity policy --zero-cost-only\n"
        "    Least-privilege CloudFormation role : infra/aws-clarity-readonly-role.yaml\n"
        "  Note: This check is a NAME HEURISTIC ONLY based solely on your caller ARN. AWS Clarity makes\n"
        "  zero extra IAM API calls to evaluate effective permissions, cannot prove this identity is an\n"
        "  administrator, and never assumes a role is read-only because its name contains 'ReadOnly'\n"
        "  (SCPs, permission boundaries, and session policies determine actual access)."
    )


def describe_credential_source(
    session,
    profile: str | None = None,
    role_arn: str | None = None,
) -> str:
    """Describe the active credential source metadata without ever reading secret values."""
    if role_arn:
        base_desc = f"profile '{profile}'" if profile else "default AWS credential chain"
        return f"assumed customer role via {base_desc} (local STS AssumeRole)"

    method = ""
    try:
        bc_sess = getattr(session, "_session", None)
        if bc_sess is not None and hasattr(bc_sess, "get_credentials"):
            creds = bc_sess.get_credentials()
            method = str(getattr(creds, "method", "") or "").strip()
    except Exception:
        method = ""

    if profile and method:
        return f"AWS CLI profile '{profile}' ({method})"
    if profile:
        return f"AWS CLI profile '{profile}'"
    if method:
        return f"default AWS credential chain ({method})"
    return "default AWS credential chain"


def enforce_identity_guards(identity: dict, allow_root: bool = False) -> dict:
    """Enforce root block (unless allow_root=True) and compute admin name-heuristic status."""
    caller_arn = str(identity.get("caller_arn") or "")
    if is_root_arn(caller_arn) and not allow_root:
        raise RootIdentityBlockedError(format_root_refusal_message(caller_arn))
    return {
        "is_root": is_root_arn(caller_arn),
        "admin_name_heuristic": is_likely_admin_name_heuristic(caller_arn),
    }


def build_policy_document(include_s3: bool = True) -> dict:
    """Return the exact least-privilege read-only IAM policy JSON derived from api_guard."""
    actions = get_allowed_iam_actions(include_s3=include_s3)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSClarityLocalReadOnlyMetadata",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",
            }
        ],
    }


def create_local_session(
    profile: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    region_name: str = "us-east-1",
) -> boto3.Session:
    """Create a local boto3.Session using the customer's AWS SDK credential chain.

    Supports AWS CLI profiles, IAM Identity Center / SSO sessions, environment
    credentials, and optional customer-owned read-only role assumption.
    Never silently falls back to ambient credentials when an explicit profile or
    role ARN fails.
    """
    try:
        base_session = (
            boto3.Session(profile_name=profile, region_name=region_name)
            if profile
            else boto3.Session(region_name=region_name)
        )
    except ProfileNotFound as exc:
        raise RuntimeError(
            f"AWS CLI profile '{profile}' was not found in ~/.aws/config or ~/.aws/credentials. "
            "Refusing to fall back to default credentials."
        ) from exc

    if not role_arn:
        return base_session

    validated_arn = validate_role_arn(role_arn)
    raw_sts = base_session.client("sts", region_name=region_name, config=SCAN_BOTO_CONFIG)
    sts = wrap_client_with_guard(raw_sts, "sts", include_s3=False, allow_assume_role=True)
    assume_kwargs = {
        "RoleArn": validated_arn,
        "RoleSessionName": "AWSClarityLocalScan",
        "DurationSeconds": 3600,
    }
    if external_id:
        assume_kwargs["ExternalId"] = validate_external_id(external_id)

    try:
        resp = sts.assume_role(**assume_kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "AccessDenied")
        raise AssumeRoleError(f"Could not assume role '{validated_arn}' ({code}).") from exc

    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region_name,
    )


def verify_identity(session) -> dict:
    """Verify active local AWS identity via sts:GetCallerIdentity (never returns credentials)."""
    try:
        raw_sts = session.client("sts", region_name="us-east-1", config=SCAN_BOTO_CONFIG)
        sts = wrap_client_with_guard(raw_sts, "sts", include_s3=False)
        ident = sts.get_caller_identity()
        return {
            "account_id": str(ident["Account"]),
            "caller_arn": str(ident.get("Arn", "")),
            "user_id": str(ident.get("UserId", "")),
        }
    except NoCredentialsError as exc:
        raise RuntimeError(
            "No active AWS credentials found. Run `aws sso login --profile <name>` or configure an AWS CLI profile first."
        ) from exc
    except TokenRetrievalError as exc:
        raise RuntimeError(
            "Your AWS SSO / IAM Identity Center token has expired. Run `aws sso login --profile <name>` and retry."
        ) from exc
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "AuthError")
        raise RuntimeError(f"AWS identity check failed ({code}): {redact_credential_strings(str(exc))}") from exc


def _minimize_report_resources_post_eval(resources: dict) -> None:
    """Prune bulky/sensitive policy & ingress structures after deterministic rule evaluation.

    Findings already retain the exact structured `evidence` fields needed by the user.
    """
    for role in resources.get("iam_roles", []) or []:
        raw = role.get("raw")
        if not isinstance(raw, dict):
            continue
        inline = raw.pop("inline_policies", None)
        if isinstance(inline, dict):
            raw["inline_policy_names"] = sorted(str(k) for k in inline.keys())
            raw["inline_policy_count"] = len(inline)
        trust = raw.pop("trust_policy", None)
        if isinstance(trust, dict):
            stmts = trust.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            raw["trust_statement_count"] = len(stmts) if isinstance(stmts, list) else 0

    for user in resources.get("iam_users", []) or []:
        raw = user.get("raw")
        if not isinstance(raw, dict):
            continue
        inline = raw.pop("inline_policies", None)
        if isinstance(inline, dict):
            raw["inline_policy_names"] = sorted(str(k) for k in inline.keys())
            raw["inline_policy_count"] = len(inline)


def run_doctor(
    session,
    include_s3_checks: bool = False,
    allow_root: bool = False,
) -> dict:
    """Verify active AWS identity, enabled regions, and exact read-only permissions."""
    cached = CachedSession(
        session,
        config=SCAN_BOTO_CONFIG,
        enforce_api_allowlist=True,
        include_s3=include_s3_checks,
    )
    identity = verify_identity(cached)
    guard_info = enforce_identity_guards(identity, allow_root=allow_root)
    enabled_regions, region_discovery = discover_enabled_regions(cached)

    permission_checks = {}

    def _probe(name: str, spec: dict) -> tuple[str, dict]:
        if name == "S3" and not include_s3_checks:
            return name, {
                "service": name,
                "status": "SKIPPED_OPTIONAL",
                "required_permission": spec["action"],
                "capability": spec["capability"],
                "message": "Skipped by default to avoid potential S3 API request charges. Pass --include-s3-checks to probe S3.",
            }
        try:
            spec["test"](cached)
            return name, {
                "service": name,
                "status": "PASSED",
                "required_permission": spec["action"],
                "capability": spec["capability"],
            }
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "AccessDenied")
            return name, {
                "service": name,
                "status": "MISSING",
                "required_permission": spec["action"],
                "capability": spec["capability"],
                "error_code": code,
                "message": f"Permission check failed ({code}).",
            }
        except Exception as exc:
            return name, {
                "service": name,
                "status": "MISSING",
                "required_permission": spec["action"],
                "capability": spec["capability"],
                "error_code": type(exc).__name__,
                "message": redact_credential_strings(str(exc)),
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(CORE_PERMISSIONS)) as ex:
        futs = [ex.submit(_probe, name, spec) for name, spec in CORE_PERMISSIONS.items()]
        for fut in concurrent.futures.as_completed(futs):
            name, entry = fut.result()
            permission_checks[name] = entry

    ordered_checks = {name: permission_checks[name] for name in CORE_PERMISSIONS if name in permission_checks}
    missing = [name for name, item in ordered_checks.items() if item["status"] == "MISSING"]

    return {
        "status": "OK" if not missing and region_discovery.get("status") == "COMPLETE" else "INCOMPLETE",
        "account_id": identity["account_id"],
        "caller_arn": identity["caller_arn"],
        "admin_name_heuristic": guard_info["admin_name_heuristic"],
        "enabled_regions": enabled_regions,
        "region_discovery": region_discovery,
        "include_s3_checks": include_s3_checks,
        "permission_checks": ordered_checks,
        "missing_services": missing,
    }


def run_local_scan(
    session,
    regions=None,
    include_s3_checks: bool = False,
    confirm_s3_request_costs: bool = False,
    deadline_s: float = 90.0,
    allow_root: bool = False,
) -> dict:
    """Execute a complete local-first multi-region read-only assessment.

    Reuses the exact same collectors (`scanner/*`) and deterministic rule engine
    (`scanner/misconfig.py`) without AWS Lambda, API Gateway, or DynamoDB.
    """
    if include_s3_checks and not confirm_s3_request_costs:
        raise ValueError(
            "Explicit consent is required before enabling optional S3 checks "
            "(pass confirm_s3_request_costs=True or confirm interactively in the CLI)."
        )

    scan_started = time.monotonic()
    is_real_boto_session = isinstance(session, boto3.Session)
    cached = CachedSession(
        session,
        config=LOCAL_BOTO_CONFIG,
        enforce_api_allowlist=True,
        include_s3=include_s3_checks,
    )

    identity = verify_identity(cached)
    enforce_identity_guards(identity, allow_root=allow_root)
    account_id = identity["account_id"]
    caller_arn = identity["caller_arn"]

    scan_all_regions = regions is None or regions == "all" or regions == ["all"]
    regional_scanners = _get_regional_scanners()

    resources = {key: [] for key in regional_scanners}
    resources["s3_buckets"] = []
    resources["iam_roles"] = []
    resources["iam_users"] = []

    scanner_statuses = []
    coverage_failures = []
    optional_checks = []

    for svc_name in ("ec2", "iam"):
        try:
            cached.client(svc_name, region_name="us-east-1" if svc_name == "ec2" else None)
        except Exception:
            pass

    if scan_all_regions:
        target_regions, region_discovery = discover_enabled_regions(cached)
    else:
        target_regions = list(dict.fromkeys(r.strip() for r in regions if isinstance(r, str) and r.strip()))
        if not target_regions:
            raise ValueError("At least one AWS region must be specified.")
        region_discovery = {"mode": "user_selected", "status": "COMPLETE", "count": len(target_regions)}

    if region_discovery.get("status") == "INCOMPLETE":
        coverage_failures.append({
            "service": "EC2",
            "label": "Region Discovery",
            "region": "global",
            "reason": region_discovery.get("reason", "Could not list enabled regions"),
            "required_permission": "ec2:DescribeRegions",
        })

    global_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    global_futures = {
        global_executor.submit(iam.scan_roles, cached): ("iam_roles", "global"),
        global_executor.submit(iam.scan_users, cached): ("iam_users", "global"),
    }

    if include_s3_checks:
        s3_region_filter = None if scan_all_regions else target_regions
        global_futures[global_executor.submit(s3.scan, cached, s3_region_filter)] = ("s3_buckets", "global")
        optional_checks.append({
            "service": "S3",
            "status": "ENABLED",
            "rules": ["S3-002", "S3-003", "S3-004", "S3-005"],
            "reason": "Enabled with explicit customer consent (--include-s3-checks).",
        })
    else:
        scanner_statuses.append(
            _scanner_status_entry(
                "s3_buckets",
                "global",
                "SKIPPED_OPTIONAL",
                0,
                "Skipped by default to avoid potential S3 API request charges outside AWS Free Tier. Re-run with --include-s3-checks to opt in.",
            )
        )
        optional_checks.append({
            "service": "S3",
            "status": "SKIPPED_OPTIONAL",
            "rules": ["S3-002", "S3-003", "S3-004", "S3-005"],
            "reason": S3_OPTIONAL_COST_NOTICE,
            "opt_in_command": "aws-clarity scan --include-s3-checks --output aws-clarity-report.json",
        })

    try:
        reg_res, reg_statuses, reg_failures = _scan_region_batch_local(
            cached,
            target_regions,
            is_real_boto_session=is_real_boto_session,
            deadline_s=deadline_s,
            probe_timeout_s=3.0,
            max_workers_cap=24,
        )
        for key, items in reg_res.items():
            if key in resources:
                resources[key].extend(items)
        scanner_statuses.extend(reg_statuses)
        coverage_failures.extend(reg_failures)

        completed_globals = set()
        remaining = max(5.0, (scan_started + deadline_s) - time.monotonic())
        try:
            for future in concurrent.futures.as_completed(global_futures.keys(), timeout=remaining):
                completed_globals.add(future)
                key, region = global_futures[future]
                meta = SCANNER_METADATA[key]
                try:
                    result = future.result()
                    resources[key].extend(result)
                    assessment_errors = _collect_assessment_errors(result)
                    if assessment_errors:
                        reason = "; ".join(f"{name}: {msg}" for name, msg in assessment_errors[:5])
                        scanner_statuses.append(_scanner_status_entry(key, region, "INCOMPLETE", len(result), reason))
                        coverage_failures.append({
                            "service": meta["service"],
                            "label": meta["label"],
                            "region": region,
                            "reason": reason,
                            "required_permission": meta["permission"],
                        })
                    else:
                        scanner_statuses.append(_scanner_status_entry(key, region, "COMPLETED", len(result)))
                except ScannerError as exc:
                    resources[key].extend(exc.resources)
                    state = "INCOMPLETE" if exc.resources else "FAILED"
                    reason = redact_credential_strings(str(exc))
                    scanner_statuses.append(_scanner_status_entry(key, region, state, len(exc.resources), reason))
                    coverage_failures.append({
                        "service": meta["service"],
                        "label": meta["label"],
                        "region": region,
                        "reason": reason,
                        "required_permission": meta["permission"],
                    })
                except Exception as exc:
                    reason = redact_credential_strings(str(exc))
                    scanner_statuses.append(_scanner_status_entry(key, region, "FAILED", 0, reason))
                    coverage_failures.append({
                        "service": meta["service"],
                        "label": meta["label"],
                        "region": region,
                        "reason": reason,
                        "required_permission": meta["permission"],
                    })
        except concurrent.futures.TimeoutError:
            pass

        for future, (key, region) in global_futures.items():
            if future in completed_globals:
                continue
            future.cancel()
            meta = SCANNER_METADATA[key]
            reason = "Collector exceeded scan time budget"
            scanner_statuses.append(_scanner_status_entry(key, region, "TIMED_OUT", 0, reason))
            coverage_failures.append({
                "service": meta["service"],
                "label": meta["label"],
                "region": region,
                "reason": reason,
                "required_permission": meta["permission"],
            })
    finally:
        global_executor.shutdown(wait=False, cancel_futures=True)

    for key in list(resources.keys()):
        resources[key] = _deduplicate_resources(resources[key])

    # Run the single shared deterministic rule engine
    resources = evaluate(cached, resources, account_id=account_id, scanner_statuses=scanner_statuses)

    # Prune raw policy documents after evaluation so full reports remain minimal
    _minimize_report_resources_post_eval(resources)

    all_resources = [
        r
        for group in resources.values()
        if isinstance(group, list)
        for r in group
    ]

    for r in all_resources:
        for chk in (r.get("assessment") or {}).get("checks", []):
            if chk.get("status") == "CHECK_FAILED":
                coverage_failures.append({
                    "service": r.get("service", ""),
                    "label": f"{r.get('name')} ({chk.get('rule_id')})",
                    "region": r.get("region", "global"),
                    "reason": chk.get("reason", "Check could not complete"),
                    "required_permission": SCANNER_METADATA.get(
                        next((k for k, v in resources.items() if r in v), ""),
                        {},
                    ).get("permission", ""),
                })

    ct_statuses = [s for s in scanner_statuses if s["key"] == "cloudtrail_trails"]
    ct_all_ok = bool(ct_statuses) and all(s["status"] == "COMPLETED" for s in ct_statuses)
    account_advisories = []
    # Only emit account-wide CT-000 when all enabled regions were discovered & scanned cleanly.
    # On user-selected partial region subsets, a multi-region trail may live in another HomeRegion.
    if (
        scan_all_regions
        and region_discovery.get("status") == "COMPLETE"
        and ct_all_ok
        and len(resources.get("cloudtrail_trails", [])) == 0
    ):
        account_advisories.append({
            "rule_id": "CT-000",
            "severity": "CRITICAL",
            "category": "Security Risk",
            "service": "CloudTrail",
            "title": "No CloudTrail trails configured in this AWS account",
            "why": (
                "Without an active multi-region CloudTrail trail, management API events older than 90 days are not "
                "archived to S3 and unauthorized changes are difficult to investigate."
            ),
            "evidence": {
                "RegionsChecked": str(len(target_regions)),
                "TrailsFound": "0",
                "Scope": "All enabled regions (DescribeTrails includeShadowTrails=False)",
            },
            "impact": (
                "Your first trail delivering a copy of management events is free in CloudTrail (S3 bucket storage costs "
                "still apply); additional management-event trails incur CloudTrail fees. Dependency check: if this is "
                "an AWS Organizations member account covered by a management-account Organization trail or CloudTrail "
                "Lake Event Data Store, confirm that coverage before creating a duplicate trail."
            ),
            "fix": (
                "First verify whether an AWS Organizations trail or CloudTrail Lake Event Data Store already covers "
                "this account. If not, open CloudTrail → Trails → Create trail, enable 'Apply trail to all regions', "
                "and enable log file validation."
            ),
            "verify": "Re-run `aws-clarity scan` across all enabled regions and import the new report to confirm an active multi-region CloudTrail trail appears.",
        })

    is_incomplete = len(coverage_failures) > 0 or any(
        (r.get("assessment") or {}).get("status") == "INCOMPLETE"
        for r in all_resources
    )

    all_issues = [issue for r in all_resources for issue in r.get("issues", [])]
    finding_counts = {
        "critical": sum(1 for i in all_issues if i.get("severity") == "CRITICAL")
        + sum(1 for a in account_advisories if a.get("severity") == "CRITICAL"),
        "warning": sum(1 for i in all_issues if i.get("severity") == "WARNING")
        + sum(1 for a in account_advisories if a.get("severity") == "WARNING"),
        "unused": sum(1 for i in all_issues if i.get("severity") == "UNUSED"),
        "info": sum(1 for i in all_issues if i.get("severity") == "INFO"),
    }
    summary = {
        "total_resources": len(all_resources),
        "critical_issues": sum(1 for r in all_resources if r.get("status") == "CRITICAL"),
        "warnings": sum(1 for r in all_resources if r.get("status") == "WARNING"),
        "unused": sum(1 for r in all_resources if r.get("status") == "UNUSED"),
        "info_observations": sum(1 for i in all_issues if i.get("severity") == "INFO"),
        "finding_counts": finding_counts,
        "healthy": sum(1 for r in all_resources if r.get("status") == "HEALTHY"),
        "incomplete_resources": sum(1 for r in all_resources if r.get("status") == "INCOMPLETE"),
        "security_risks": sum(1 for i in all_issues if i.get("category") == "Security Risk")
        + sum(1 for a in account_advisories if a.get("category") == "Security Risk"),
        "operational_concerns": sum(1 for i in all_issues if i.get("category") == "Operational Concern"),
        "potential_cost_waste": sum(1 for i in all_issues if i.get("category") == "Potential Cost Waste"),
        "cost_risk_findings": sum(
            1
            for i in all_issues
            if i.get("category") in ("Potential Cost Waste", "Cost Risk", "Unused") or i.get("severity") == "UNUSED"
        ),
        "health_score_available": not is_incomplete,
    }

    service_summary = []
    for svc_entry in SERVICE_COVERAGE_MATRIX:
        svc_name = svc_entry["service"]
        keys = [rt["key"] for rt in svc_entry["resource_types"]]
        svc_statuses = [s for s in scanner_statuses if s["key"] in keys]
        svc_resources_count = sum(len(resources.get(k, [])) for k in keys)
        svc_failures = [f for f in coverage_failures if f.get("service") == svc_name]

        if svc_statuses and all(s["status"] == "SKIPPED_OPTIONAL" for s in svc_statuses):
            svc_state = "SKIPPED_OPTIONAL"
        elif svc_failures or any(s["status"] not in ("COMPLETED", "SKIPPED_OPTIONAL") for s in svc_statuses):
            svc_state = "INCOMPLETE"
        else:
            svc_state = "COMPLETE"

        service_summary.append({
            "service": svc_name,
            "scope": svc_entry["scope"],
            "status": svc_state,
            "resource_count": svc_resources_count,
            "failure_count": len(svc_failures),
            "resource_types": svc_entry["resource_types"],
        })

    permission_checks = {}
    for svc_name, spec in CORE_PERMISSIONS.items():
        if svc_name == "S3" and not include_s3_checks:
            permission_checks[svc_name] = {
                "service": svc_name,
                "status": "SKIPPED_OPTIONAL",
                "required_permission": spec["action"],
                "capability": spec["capability"],
                "message": "Optional S3 checks skipped by default (--include-s3-checks to opt in).",
            }
            continue
        svc_failures = [f for f in coverage_failures if f.get("service") == svc_name]
        permission_checks[svc_name] = {
            "service": svc_name,
            "status": "MISSING" if svc_failures else "PASSED",
            "required_permission": spec["action"],
            "capability": spec["capability"],
            **({"message": svc_failures[0]["reason"]} if svc_failures else {}),
        }

    failed_region_set = {
        s["region"]
        for s in scanner_statuses
        if s.get("region") in target_regions and s.get("status") not in ("COMPLETED", "SKIPPED_OPTIONAL")
    }
    regions_succeeded = [r for r in target_regions if r not in failed_region_set]
    regions_failed = [r for r in target_regions if r in failed_region_set]

    coverage = {
        "status": "INCOMPLETE" if is_incomplete else "COMPLETE",
        "is_partial": is_incomplete,
        "region_discovery": region_discovery,
        "regions_scanned": target_regions,
        "regions_succeeded": regions_succeeded,
        "regions_failed": regions_failed,
        "services_supported": [s["service"] for s in SERVICE_COVERAGE_MATRIX],
        "services_scanned": sorted({s["service"] for s in scanner_statuses if s["status"] in ("COMPLETED", "INCOMPLETE")}),
        "services_complete": [s["service"] for s in service_summary if s["status"] == "COMPLETE"],
        "services_skipped_optional": [s["service"] for s in service_summary if s["status"] == "SKIPPED_OPTIONAL"],
        "optional_checks": optional_checks,
        "service_matrix": SERVICE_COVERAGE_MATRIX,
        "service_summary": service_summary,
        "resources_inspected": len(all_resources),
        "findings_detected": len(all_issues),
        "failures": coverage_failures,
        "unsupported_services": OUT_OF_SCOPE_DISCLOSURES,
        "scanner_statuses": scanner_statuses,
        "rules_catalog": get_rules_catalog(),
    }

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scanner_version": CLI_VERSION,
        "execution_mode": "local-cli",
        "status": "INCOMPLETE" if is_incomplete else "COMPLETE",
        "scan_state": "INCOMPLETE" if is_incomplete else "COMPLETE",
        "account_id": account_id,
        "caller_arn": caller_arn,
        "region": "all-enabled-regions" if scan_all_regions else (target_regions[0] if len(target_regions) == 1 else "multi-region"),
        "regions": target_regions,
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "scan_duration_ms": int((time.monotonic() - scan_started) * 1000),
        "partial": is_incomplete,
        "summary": summary,
        "account_advisories": account_advisories,
        "coverage": coverage,
        "permission_checks": permission_checks,
        "resources": resources,
    }
