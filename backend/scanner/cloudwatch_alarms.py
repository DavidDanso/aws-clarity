from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("cloudwatch", region_name="us-east-1")
        paginator = client.get_paginator("describe_alarms")
        pages = paginator.paginate()
        for page in pages:
            for alarm in page.get("MetricAlarms", []):
                name = alarm.get("AlarmName")
                actions_enabled = alarm.get("ActionsEnabled", True)
                state_value = alarm.get("StateValue")
                
                status = "HEALTHY"
                issues = []
                
                if not actions_enabled:
                    status = "WARNING"
                    issues.append("Alarm actions are disabled — this alarm will not trigger notifications")
                
                if state_value == "INSUFFICIENT_DATA":
                    status = "WARNING"
                    issues.append("Alarm has insufficient data — it may be pointing to a deleted metric")
                    
                resources.append({
                    "id": name,
                    "name": name,
                    "type": "cloudwatch_alarm",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "alarm_arn": alarm.get("AlarmArn"),
                        "state_value": state_value,
                        "metric_name": alarm.get("MetricName"),
                        "namespace": alarm.get("Namespace"),
                        "actions_enabled": actions_enabled
                    }
                })
    except ClientError as e:
        logging.warning(f"Error scanning CloudWatch alarms: {e}")
    return resources
