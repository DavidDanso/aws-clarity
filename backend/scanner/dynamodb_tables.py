from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []
    try:
        client = session.client("dynamodb", region_name="us-east-1")
        tables = []
        kwargs = {}
        while True:
            response = client.list_tables(**kwargs)
            tables.extend(response.get("TableNames", []))
            if "LastEvaluatedTableName" not in response:
                break
            kwargs["ExclusiveStartTableName"] = response["LastEvaluatedTableName"]

        for name in tables:
            try:
                table_info = client.describe_table(TableName=name).get("Table", {})
                sse_desc = table_info.get("SSEDescription", {})
                
                status = "HEALTHY"
                issues = []
                
                if not sse_desc or sse_desc.get("Status") != "ENABLED":
                    status = "WARNING"
                    issues.append("Table is not encrypted with a KMS key")
                
                resources.append({
                    "id": name,
                    "name": name,
                    "type": "dynamodb_table",
                    "status": status,
                    "issues": issues,
                    "raw": {
                        "table_status": table_info.get("TableStatus"),
                        "item_count": table_info.get("ItemCount"),
                        "table_size_bytes": table_info.get("TableSizeBytes"),
                        "creation_date_time": table_info.get("CreationDateTime"),
                        "sse_description": sse_desc
                    }
                })
            except ClientError as e:
                logging.warning(f"Error describing DynamoDB table {name}: {e}")
    except ClientError as e:
        logging.warning(f"Error listing DynamoDB tables: {e}")
    return resources
