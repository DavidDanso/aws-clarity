from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("cloudformation", region_name="us-east-1")
        paginator = client.get_paginator("describe_stacks")
        pages = paginator.paginate()
        for page in pages:
            for stack in page.get("Stacks", []):
                name = stack.get("StackName")
                stack_id = stack.get("StackId")
                stack_status = stack.get("StackStatus")
                term_protection = stack.get("EnableTerminationProtection", False)
                
                status = "HEALTHY"
                issues = []
                
                if stack_status in ["ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "DELETE_FAILED"]:
                    status = "ORPHANED"
                    issues.append("Stack is in a failed state and may need cleanup")
                elif not term_protection:
                    status = "WARNING"
                    issues.append("Termination protection is disabled")
                    
                resources.append({
                    "id": name,
                    "name": name,
                    "type": "cloudformation_stack",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "stack_id": stack_id,
                        "stack_status": stack_status,
                        "creation_time": stack.get("CreationTime"),
                        "last_updated_time": stack.get("LastUpdatedTime"),
                        "enable_termination_protection": term_protection
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning CloudFormation stacks: {e}")
    return resources
