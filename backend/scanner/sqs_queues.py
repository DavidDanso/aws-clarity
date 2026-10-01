from botocore.exceptions import ClientError
from exceptions import ScannerError
import logging

def scan(session, region="us-east-1"):
    resources = []
    try:
        client = session.client("sqs", region_name=region)
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
                    "region": region,
                    "raw": {
                        "approximate_number_of_messages": attributes.get("ApproximateNumberOfMessages"),
                        "created_timestamp": attributes.get("CreatedTimestamp"),
                        "kms_master_key_id": kms_master_key_id,
                        "sqs_managed_sse_enabled": attributes.get("SqsManagedSseEnabled"),
                    }
                })
            except ClientError:
                raise
    except ClientError as e:
        raise ScannerError(str(e), resources) from e
    return resources
