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
                role_id = role.get("RoleId")
                
                # Retrieve inline policies
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
                    logging.warning(f"Error getting policies for role {role_name}: {e}")

                resources.append({
                    "id": role_id,
                    "name": role_name,
                    "type": "iam_role",
                    "status": "HEALTHY",
                    "issues": [],
                    "raw": {
                        "role_name": role_name,
                        "arn": role.get("Arn"),
                        "create_date": role.get("CreateDate"),
                        "inline_policies": inline_policies
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning IAM Roles: {e}")
    return resources
