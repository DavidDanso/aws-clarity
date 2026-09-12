from botocore.exceptions import ClientError
import logging
import urllib.parse
import json


def scan(session):
    resources = []
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_roles")
        pages = paginator.paginate()
        for page in pages:
            for role in page.get("Roles", []):
                role_name = role.get("RoleName")
                role_id   = role.get("RoleId")

                # ---- Inline policies ----
                inline_policies = {}
                try:
                    policy_names_resp = iam.list_role_policies(RoleName=role_name)
                    for policy_name in policy_names_resp.get("PolicyNames", []):
                        policy_doc_resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                        raw_doc = policy_doc_resp.get("PolicyDocument", {})
                        if isinstance(raw_doc, str):
                            doc = json.loads(urllib.parse.unquote(raw_doc))
                        else:
                            doc = raw_doc
                        inline_policies[policy_name] = doc
                except ClientError as e:
                    logging.warning(f"Error getting inline policies for role {role_name}: {e}")

                # ---- Attached managed policies ----
                attached_managed_policies = []
                try:
                    attached_resp = iam.list_attached_role_policies(RoleName=role_name)
                    for p in attached_resp.get("AttachedPolicies", []):
                        attached_managed_policies.append({
                            "PolicyName": p.get("PolicyName"),
                            "PolicyArn":  p.get("PolicyArn"),
                        })
                except ClientError as e:
                    logging.warning(f"Error getting attached policies for role {role_name}: {e}")

                # ---- Trust policy (AssumeRolePolicyDocument) ----
                trust_policy_raw = role.get("AssumeRolePolicyDocument", {})
                if isinstance(trust_policy_raw, str):
                    try:
                        trust_policy = json.loads(urllib.parse.unquote(trust_policy_raw))
                    except Exception:
                        trust_policy = {}
                else:
                    trust_policy = trust_policy_raw

                resources.append({
                    "id":     role_id,
                    "name":   role_name,
                    "type":   "iam_role",
                    "status": "HEALTHY",
                    "issues": [],
                    "region": "global",
                    "raw": {
                        "role_name":                role_name,
                        "arn":                      role.get("Arn"),
                        "create_date":              role.get("CreateDate"),
                        "inline_policies":          inline_policies,
                        "attached_managed_policies": attached_managed_policies,
                        "trust_policy":             trust_policy,
                    },
                })
    except ClientError as e:
        logging.warning(f"Error scanning IAM Roles: {e}")
    return resources
