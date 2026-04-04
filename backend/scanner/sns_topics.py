from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("sns", region_name="us-east-1")
        paginator = client.get_paginator("list_topics")
        pages = paginator.paginate()
        for page in pages:
            for topic in page.get("Topics", []):
                arn = topic.get("TopicArn")
                if not arn:
                    continue
                try:
                    name = arn.split(":")[-1]
                    attributes = client.get_topic_attributes(TopicArn=arn).get("Attributes", {})
                    
                    kms_master_key_id = attributes.get("KmsMasterKeyId")
                    status = "HEALTHY"
                    issues = []
                    
                    if not kms_master_key_id:
                        status = "WARNING"
                        issues.append("Topic is not encrypted with a KMS key")
                        
                    resources.append({
                        "id": arn,
                        "name": name,
                        "type": "sns_topic",
                        "status": status,
                        "issues": issues,
                        "raw": {
                            "subscriptions_confirmed": attributes.get("SubscriptionsConfirmed"),
                            "kms_master_key_id": kms_master_key_id
                        }
                    })
                except ClientError as e:
                    logging.warning(f"Error describing SNS topic {arn}: {e}")
    except ClientError as e:
        logging.warning(f"Error scanning SNS topics: {e}")
    return resources
