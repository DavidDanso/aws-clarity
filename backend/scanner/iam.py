import concurrent.futures
import json
import urllib.parse
from botocore.exceptions import ClientError
from exceptions import ScannerError


def _paginate_policy_names(iam_client, paginator_name, **kwargs):
    names = []
    paginator = iam_client.get_paginator(paginator_name)
    for page in paginator.paginate(**kwargs):
        names.extend(page.get("PolicyNames", []))
    return names


def _paginate_attached_policies(iam_client, paginator_name, **kwargs):
    attached = []
    paginator = iam_client.get_paginator(paginator_name)
    for page in paginator.paginate(**kwargs):
        for p in page.get("AttachedPolicies", []):
            attached.append({
                "PolicyName": p.get("PolicyName"),
                "PolicyArn": p.get("PolicyArn"),
            })
    return attached


def _decode_policy_doc(raw_doc):
    if isinstance(raw_doc, str):
        try:
            return json.loads(urllib.parse.unquote(raw_doc))
        except Exception:
            return {}
    return raw_doc if isinstance(raw_doc, dict) else {}


def _inspect_role(iam, role):
    role_name = role.get("RoleName")
    role_id = role.get("RoleId")
    role_path = role.get("Path", "/")
    assessment_errors = {}

    # Paginated inline policies
    inline_policies = {}
    try:
        for policy_name in _paginate_policy_names(iam, "list_role_policies", RoleName=role_name):
            policy_doc_resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            inline_policies[policy_name] = _decode_policy_doc(policy_doc_resp.get("PolicyDocument", {}))
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "AWS error")
        inline_policies = None
        for rule_id in ("IAM-001", "IAM-002", "IAM-006"):
            assessment_errors[rule_id] = f"Could not read inline policies: {code}"

    # Paginated attached managed policies
    try:
        attached_managed_policies = _paginate_attached_policies(
            iam, "list_attached_role_policies", RoleName=role_name
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "AWS error")
        attached_managed_policies = None
        for rule_id in ("IAM-003", "IAM-004", "IAM-007"):
            assessment_errors[rule_id] = f"Could not list attached policies: {code}"

    trust_policy = _decode_policy_doc(role.get("AssumeRolePolicyDocument", {}))

    item = {
        "id": role_id,
        "name": role_name,
        "type": "iam_role",
        "service": "IAM",
        "status": "INCOMPLETE",
        "issues": [],
        "region": "global",
        "raw": {
            "role_name": role_name,
            "arn": role.get("Arn"),
            "path": role_path,
            "is_service_linked": role_path.startswith("/aws-service-role/"),
            "create_date": role.get("CreateDate"),
            "inline_policies": inline_policies,
            "attached_managed_policies": attached_managed_policies,
            "trust_policy": trust_policy,
        },
    }
    if assessment_errors:
        item["assessment_errors"] = assessment_errors
    return item


def scan_roles(session):
    resources = []
    roles = []
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            roles.extend(page.get("Roles", []))
    except ClientError as e:
        raise ScannerError(str(e), resources) from e

    if not roles:
        return resources

    workers = min(16, len(roles))
    if workers == 1:
        return [_inspect_role(iam, roles[0])]

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        resources = list(ex.map(lambda role: _inspect_role(iam, role), roles))
    return resources


def _inspect_user(iam, user):
    user_name = user.get("UserName")
    user_id = user.get("UserId")
    assessment_errors = {}

    def fetch_mfa():
        devices = []
        for mfa_page in iam.get_paginator("list_mfa_devices").paginate(UserName=user_name):
            devices.extend(mfa_page.get("MFADevices", []))
        return devices

    def fetch_keys():
        keys = []
        for key_page in iam.get_paginator("list_access_keys").paginate(UserName=user_name):
            for k in key_page.get("AccessKeyMetadata", []):
                keys.append({
                    "access_key_id": k.get("AccessKeyId"),
                    "status": k.get("Status"),
                    "create_date": k.get("CreateDate"),
                })
        return keys

    def fetch_attached():
        return _paginate_attached_policies(iam, "list_attached_user_policies", UserName=user_name)

    def fetch_inline():
        docs = {}
        for policy_name in _paginate_policy_names(iam, "list_user_policies", UserName=user_name):
            policy_doc_resp = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            docs[policy_name] = _decode_policy_doc(policy_doc_resp.get("PolicyDocument", {}))
        return docs

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        f_mfa = ex.submit(fetch_mfa)
        f_keys = ex.submit(fetch_keys)
        f_attached = ex.submit(fetch_attached)
        f_inline = ex.submit(fetch_inline)

        try:
            mfa_devices = f_mfa.result()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "AWS error")
            mfa_devices = None
            assessment_errors["IAM-009"] = f"Could not inspect MFA devices: {code}"

        try:
            access_keys = f_keys.result()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "AWS error")
            access_keys = None
            assessment_errors["IAM-010"] = f"Could not inspect access keys: {code}"

        try:
            attached_managed_policies = f_attached.result()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "AWS error")
            attached_managed_policies = None
            assessment_errors["IAM-011"] = f"Could not list attached user policies: {code}"

        try:
            inline_policies = f_inline.result()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "AWS error")
            inline_policies = None
            assessment_errors["IAM-011"] = f"Could not read user inline policies: {code}"

    item = {
        "id": user_id,
        "name": user_name,
        "type": "iam_user",
        "service": "IAM",
        "status": "INCOMPLETE",
        "issues": [],
        "region": "global",
        "raw": {
            "user_name": user_name,
            "arn": user.get("Arn"),
            "path": user.get("Path", "/"),
            "create_date": user.get("CreateDate"),
            "password_last_used": user.get("PasswordLastUsed"),
            "mfa_devices_count": len(mfa_devices) if isinstance(mfa_devices, list) else None,
            "access_keys": access_keys,
            "attached_managed_policies": attached_managed_policies,
            "inline_policies": inline_policies,
        },
    }
    if assessment_errors:
        item["assessment_errors"] = assessment_errors
    return item


def scan_users(session):
    resources = []
    users = []
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
    except ClientError as e:
        raise ScannerError(str(e), resources) from e

    if not users:
        return resources

    workers = min(12, len(users))
    if workers == 1:
        return [_inspect_user(iam, users[0])]

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        resources = list(ex.map(lambda user: _inspect_user(iam, user), users))
    return resources


# Backwards-compatible alias for role scanning
scan = scan_roles
