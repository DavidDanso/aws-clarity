from botocore.exceptions import ClientError
from exceptions import ScannerError


def scan_alarms(session, region="us-east-1"):
    resources = []
    try:
        cw = session.client("cloudwatch", region_name=region)
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate():
            for alarm in page.get("MetricAlarms", []):
                alarm_name = alarm.get("AlarmName")
                alarm_arn = alarm.get("AlarmArn")
                # Data minimization: drop AlarmDescription, Dimensions, and raw action ARNs.
                resources.append({
                    "id": alarm_name,
                    "name": alarm_name,
                    "type": "cloudwatch_alarm",
                    "service": "CloudWatch",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "arn": alarm_arn,
                        "alarm_type": "MetricAlarm",
                        "namespace": alarm.get("Namespace"),
                        "metric_name": alarm.get("MetricName"),
                        "state_value": alarm.get("StateValue"),
                        "actions_enabled": alarm.get("ActionsEnabled"),
                        "alarm_actions_count": len(alarm.get("AlarmActions", []) or []),
                    },
                })
            for alarm in page.get("CompositeAlarms", []):
                alarm_name = alarm.get("AlarmName")
                alarm_arn = alarm.get("AlarmArn")
                resources.append({
                    "id": alarm_name,
                    "name": alarm_name,
                    "type": "cloudwatch_alarm",
                    "service": "CloudWatch",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "arn": alarm_arn,
                        "alarm_type": "CompositeAlarm",
                        "state_value": alarm.get("StateValue"),
                        "actions_enabled": alarm.get("ActionsEnabled"),
                        "alarm_actions_count": len(alarm.get("AlarmActions", []) or []),
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources


def scan_log_groups(session, region="us-east-1"):
    resources = []
    try:
        logs = session.client("logs", region_name=region)
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                lg_name = lg.get("logGroupName")
                # Data minimization: keep has_kms_key boolean instead of full kmsKeyId ARN.
                resources.append({
                    "id": lg_name,
                    "name": lg_name,
                    "type": "cloudwatch_log_group",
                    "service": "CloudWatch",
                    "status": "INCOMPLETE",
                    "issues": [],
                    "region": region,
                    "raw": {
                        "arn": lg.get("arn"),
                        "retention_in_days": lg.get("retentionInDays"),
                        "stored_bytes": lg.get("storedBytes", 0),
                        "has_kms_key": bool(lg.get("kmsKeyId")),
                        "log_group_class": lg.get("logGroupClass", "STANDARD"),
                        "creation_time": lg.get("creationTime"),
                    },
                })
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
