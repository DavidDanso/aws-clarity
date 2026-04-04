from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("sqs", region_name="us-east-1")
        queue_urls = []
        kwargs = {"MaxResults": 1000}
        while True:
            response = client.list_queues(**kwargs)
            queue_urls.extend(response.get("QueueUrls", []))
            if "NextToken" not in response:
                break
            kwargs["NextToken"] = response["NextToken"]

        for url in queue_urls:
            try:
                name = url.split("/")[-1]
                attributes = client.get_queue_attributes(QueueUrl=url, AttributeNames=["All"]).get("Attributes", {})
                
                kms_master_key_id = attributes.get("KmsMasterKeyId")
                status = "HEALTHY"
                issues = []
                
                if not kms_master_key_id:
                    status = "WARNING"
                    issues.append("Queue is not encrypted with a KMS key")
                    
                resources.append({
                    "id": attributes.get("QueueArn", url),
                    "name": name,
                    "type": "sqs_queue",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "approximate_number_of_messages": attributes.get("ApproximateNumberOfMessages"),
                        "created_timestamp": attributes.get("CreatedTimestamp"),
                        "kms_master_key_id": kms_master_key_id
                    }
                })
            except ClientError as e:
                logging.warning(f"Error describing SQS queue {url}: {e}")
    except ClientError as e:
        logging.warning(f"Error listing SQS queues: {e}")
    return resources
