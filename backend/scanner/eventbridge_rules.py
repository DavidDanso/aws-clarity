from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("events", region_name="us-east-1")
        rules = []
        kwargs = {}
        while True:
            response = client.list_rules(**kwargs)
            rules.extend(response.get("Rules", []))
            if "NextToken" not in response:
                break
            kwargs["NextToken"] = response["NextToken"]

        for rule in rules:
            name = rule.get("Name")
            state = rule.get("State")
            
            status = "HEALTHY"
            issues = []
            
            if state == "DISABLED":
                status = "ORPHANED"
                issues.append("EventBridge rule is disabled — verify it is still needed")
                
            resources.append({
                "id": name,
                "name": name,
                "type": "eventbridge_rule",
                "status": status,
                "issues": issues,
                "raw": {
                    "arn": rule.get("Arn"),
                    "state": state,
                    "schedule_expression": rule.get("ScheduleExpression"),
                    "description": rule.get("Description")
                }
            })
    except ClientError as e:
        logging.warning(f"Error scanning EventBridge rules: {e}")
    return resources
